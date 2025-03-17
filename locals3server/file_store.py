import os
import hashlib
from datetime import datetime
import shutil
import re
from typing import BinaryIO, Optional, List
from .db import Database
from .models import Bucket, BucketQuery, S3Item
from .errors import BucketNotEmpty, NoSuchBucket, InvalidKeyName
import configparser
import mimetypes
import urllib.parse
import logging

CONTENT_FILE = '.s3local_content'
METADATA_FILE = '.s3local_metadata'
VALID_KEY_PATTERN = re.compile(r'^[a-zA-Z0-9\-_./]+$')

class FileStore:
    CHUNK_SIZE = 8 * 1024 * 1024  # 8MB chunks for streaming

    def __init__(self, root):
        self.root = root
        self.files_dir = os.path.join(root, 'files')
        if not os.path.exists(self.files_dir):
            os.makedirs(self.files_dir)
        self.db = Database(root)
        self._buckets = None
        self._check_and_rebuild_if_needed()

    def _check_and_rebuild_if_needed(self):
        """Check if database needs rebuilding and rebuild if necessary"""
        try:
            # Try to list buckets - this will fail if DB is corrupted or missing
            with self.db._get_connection() as conn:
                conn.execute('SELECT COUNT(*) FROM buckets').fetchone()
        except Exception as e:
            print(f"Database check failed: {e}. Rebuilding database from filesystem...")
            self._rebuild_database()

    def _rebuild_database(self):
        """Rebuild database from filesystem"""
        # Drop and recreate tables
        self.db._drop_tables()
        self.db._create_tables()
        
        # Reset bucket cache
        self._buckets = None

        # Scan root directory for buckets
        for bucket_name in os.listdir(self.root):
            bucket_path = os.path.join(self.root, bucket_name)
            if not os.path.isdir(bucket_path) or bucket_name == 'files':
                continue

            # Create bucket using create_bucket method
            bucket = self.create_bucket(bucket_name)
            bucket_id = self.db._get_bucket_id(bucket_name)

            # Scan bucket for objects
            for root, dirs, files in os.walk(bucket_path):
                for file in files:
                    # Skip metadata files
                    if file in [CONTENT_FILE, METADATA_FILE, '.s3local.db']:
                        continue

                    # Get relative path from bucket root
                    full_path = os.path.join(root, file)
                    rel_path = os.path.relpath(full_path, bucket_path)

                    # Calculate object metadata
                    with open(full_path, 'rb') as f:
                        content = f.read()
                        md5 = hashlib.md5(content, usedforsecurity=False).hexdigest()
                        size = len(content)

                    # Try to get content type
                    content_type = self._guess_content_type(rel_path)

                    # Get file timestamps
                    stats = os.stat(full_path)
                    created_at = datetime.fromtimestamp(stats.st_ctime).strftime('%Y-%m-%dT%H:%M:%S.000Z')
                    modified_at = datetime.fromtimestamp(stats.st_mtime).strftime('%Y-%m-%dT%H:%M:%S.000Z')

                    # Store in database directly
                    with self.db._get_connection() as conn:
                        conn.execute('''
                            INSERT INTO objects (
                                bucket_id, key, size, content_type, md5, 
                                storage_path, created_at, modified_at
                            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                        ''', (
                            bucket_id, rel_path, size, content_type, md5,
                            full_path, created_at, modified_at
                        ))

        # Reset bucket cache again to ensure fresh data
        self._buckets = None

    def _guess_content_type(self, path: str) -> str:
        """Guess content type from file path"""
        content_type, _ = mimetypes.guess_type(path)
        return content_type or 'application/octet-stream'

    @property
    def buckets(self) -> List[Bucket]:
        """Get list of buckets (always fresh from database)"""
        return self.get_all_buckets()

    def _calculate_storage_path(self, bucket_name: str, key: str, md5: str) -> str:
        """Calculate a file storage path that preserves original file structure"""
        # Store files in bucket directory with original path structure
        return os.path.join(self.root, bucket_name, key)

    def _stream_file(self, source: BinaryIO, chunk_size: int = CHUNK_SIZE):
        """Stream a file in chunks to calculate MD5 and size"""
        md5 = hashlib.md5(usedforsecurity=False)
        size = 0
        while True:
            chunk = source.read(chunk_size)
            if not chunk:
                break
            md5.update(chunk)
            size += len(chunk)
            yield chunk
        source.seek(0)
        yield md5.hexdigest(), size

    def get_all_buckets(self):
        """List all buckets"""
        buckets = []
        with self.db._get_connection() as conn:
            for row in conn.execute('SELECT name, created_at FROM buckets ORDER BY name'):
                buckets.append(Bucket(row['name'], row['created_at']))
        return buckets

    def get_bucket(self, bucket_name):
        """Get a bucket by name"""
        if not self._buckets:
            self._buckets = self.get_all_buckets()
        
        for bucket in self._buckets:
            if bucket.name == bucket_name:
                return bucket
        
        # If bucket not found, raise NoSuchBucket exception
        raise NoSuchBucket()

    def create_bucket(self, bucket_name: str) -> Bucket:
        """Create a new bucket"""
        if bucket_name not in [bucket.name for bucket in self.buckets]:
            try:
                os.makedirs(os.path.join(self.root, bucket_name))
            except OSError as e:
                # Log the error but continue if it's just that the directory already exists
                if e.errno != 17:  # 17 is EEXIST (File exists)
                    logging.warning(f"Error creating bucket directory: {e}")
                self.db.create_bucket(bucket_name)
            self._buckets = None  # Reset cache
        return self.get_bucket(bucket_name)

    def delete_bucket(self, bucket_name: str):
        """Delete a bucket if it's empty"""
        bucket = self.get_bucket(bucket_name)
        if not bucket:
            raise NoSuchBucket

        # First check if bucket is empty in database
        if not self.db.delete_bucket(bucket_name):
            raise BucketNotEmpty

        try:
            # Then try to delete from filesystem
            bucket_path = os.path.join(self.root, bucket_name)
            if os.path.exists(bucket_path):
                for root, dirs, files in os.walk(bucket_path, topdown=False):
                    for name in files:
                        os.remove(os.path.join(root, name))
                    for name in dirs:
                        os.rmdir(os.path.join(root, name))
                os.rmdir(bucket_path)
            self._buckets = None  # Reset cache
        except OSError as e:
            if e.errno == 2:  # No such file or directory
                # If filesystem is already gone but DB deletion succeeded, that's fine
                pass
            else:
                # For any other error, assume bucket not empty
                raise BucketNotEmpty

    def get_all_keys(self, bucket: Bucket, **kwargs):
        """List all keys in a bucket with pagination"""
        max_keys = int(kwargs.get('max_keys', 1000))
        prefix = kwargs.get('prefix', '')
        
        objects = self.db.list_objects(bucket.name, prefix, max_keys + 1)
        matches = []
        is_truncated = False

        for obj in objects[:max_keys]:
            matches.append(S3Item(
                obj['key'],
                size=obj['size'],
                md5=obj['md5'],
                content_type=obj['content_type'],
                creation_date=obj['created_at'],
                modified_date=obj['modified_at']
            ))

        if len(objects) > max_keys:
            is_truncated = True

        return BucketQuery(bucket, matches, is_truncated, **kwargs)

    def get_item(self, bucket_name: str, item_name: str) -> Optional[S3Item]:
        """Get an item from a bucket"""
        obj = self.db.get_object(bucket_name, item_name)
        if not obj:
            return None

        item = S3Item(
            item_name,
            size=obj['size'],
            md5=obj['md5'],
            content_type=obj['content_type'],
            creation_date=obj['created_at'],
            modified_date=obj['modified_at']
        )
        try:
            item.io = open(obj['storage_path'], 'rb')
        except FileNotFoundError:
            return None
        return item

    def _validate_key_name(self, key: str) -> bool:
        """Validate that the key name contains only allowed characters"""
        # Check the entire key
        if not VALID_KEY_PATTERN.match(key):
            raise InvalidKeyName(f"Key name '{key}' contains invalid characters. Only alphanumeric characters, hyphens, underscores, periods, and forward slashes are allowed.")
        
        # Also check each path component separately
        for part in key.split('/'):
            if part and not re.match(r'^[a-zA-Z0-9\-_.]+$', part):
                raise InvalidKeyName(f"Path component '{part}' in key '{key}' contains invalid characters. Only alphanumeric characters, hyphens, underscores, and periods are allowed in path components.")
        
        return True

    def store_data(self, bucket: Bucket, item_name: str, headers: dict, data: bytes) -> S3Item:
        """Store data from bytes"""
        # Validate key name
        self._validate_key_name(item_name)
        
        md5 = hashlib.md5(data, usedforsecurity=False).hexdigest()
        size = len(data)
        content_type = headers.get('content-type', 'application/octet-stream')
        if 'content-length' not in headers:
            headers['content-length'] = str(size)
        
        # Store files in bucket directory with original path structure
        storage_path = os.path.join(self.root, bucket.name, item_name)
        
        # Create parent directories if they don't exist
        parent_dir = os.path.dirname(storage_path)
        if parent_dir:
            os.makedirs(parent_dir, exist_ok=True)
        
        # Write the file
        with open(storage_path, 'wb') as f:
            f.write(data)
        
        # Update database
        self.db.put_object(bucket.name, item_name, size, content_type, md5, storage_path)
        
        return S3Item(
            item_name,
            size=size,
            md5=md5,
            content_type=content_type,
            creation_date=datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S.000Z')
        )

    def store_item(self, bucket: Bucket, item_name: str, handler) -> S3Item:
        """Store an item from a request handler with streaming support"""
        # Validate key name
        self._validate_key_name(item_name)
        
        headers = {k.lower(): v for k, v in handler.headers.items()}
        content_type = headers.get('content-type', 'application/octet-stream')
        
        # Stream the file to calculate MD5 and size
        chunks = []
        md5 = None
        size = None
        
        for chunk in self._stream_file(handler.rfile):
            if isinstance(chunk, tuple):
                md5, size = chunk
            else:
                chunks.append(chunk)
        
        # Store files in bucket directory with original path structure
        storage_path = os.path.join(self.root, bucket.name, item_name)
        
        # Create parent directories if they don't exist
        parent_dir = os.path.dirname(storage_path)
        if parent_dir:
            os.makedirs(parent_dir, exist_ok=True)
        
        # Write the file
        with open(storage_path, 'wb') as f:
            for chunk in chunks:
                f.write(chunk)
        
        # Update database
        self.db.put_object(bucket.name, item_name, size, content_type, md5, storage_path)
        
        return S3Item(
            item_name,
            size=size,
            md5=md5,
            content_type=content_type,
            creation_date=datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S.000Z')
        )

    def delete_item(self, bucket_name: str, item_name: str):
        """Delete an item from a bucket"""
        obj = self.db.get_object(bucket_name, item_name)
        if obj and os.path.exists(obj['storage_path']):
            os.remove(obj['storage_path'])
        self.db.delete_object(bucket_name, item_name)

    def copy_item(self, src_bucket_name: str, src_name: str, bucket_name: str, name: str, handler) -> S3Item:
        """Copy an item from one location to another"""
        # Validate key names
        self._validate_key_name(src_name)
        self._validate_key_name(name)
        
        src_obj = self.db.get_object(src_bucket_name, src_name)
        if not src_obj:
            raise NoSuchBucket
            
        # Store files in bucket directory with original path structure
        storage_path = os.path.join(self.root, bucket_name, name)
        
        # Create parent directories if they don't exist
        parent_dir = os.path.dirname(storage_path)
        if parent_dir:
            os.makedirs(parent_dir, exist_ok=True)
        
        # Copy the file
        shutil.copy2(src_obj['storage_path'], storage_path)
        
        # Update database
        self.db.put_object(
            bucket_name, name,
            src_obj['size'],
            src_obj['content_type'],
            src_obj['md5'],
            storage_path
        )
        
        return S3Item(
            name,
            size=src_obj['size'],
            md5=src_obj['md5'],
            content_type=src_obj['content_type'],
            creation_date=datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S.000Z')
        ) 