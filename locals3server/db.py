import sqlite3
import os
from datetime import datetime
from contextlib import contextmanager

class Database:
    def __init__(self, root_dir):
        self.db_path = os.path.join(root_dir, '.s3local.db')
        self._init_db()
    
    def _init_db(self):
        # Ensure the database directory exists
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        
        with self._get_connection() as conn:
            conn.executescript('''
                CREATE TABLE IF NOT EXISTS buckets (
                    id INTEGER PRIMARY KEY,
                    name TEXT UNIQUE NOT NULL,
                    created_at TIMESTAMP NOT NULL
                );

                CREATE TABLE IF NOT EXISTS objects (
                    id INTEGER PRIMARY KEY,
                    bucket_id INTEGER NOT NULL,
                    key TEXT NOT NULL,
                    size BIGINT NOT NULL,
                    content_type TEXT NOT NULL,
                    md5 TEXT NOT NULL,
                    storage_path TEXT NOT NULL,
                    created_at TIMESTAMP NOT NULL,
                    modified_at TIMESTAMP,
                    FOREIGN KEY (bucket_id) REFERENCES buckets(id),
                    UNIQUE (bucket_id, key)
                );

                CREATE INDEX IF NOT EXISTS idx_bucket_key ON objects(bucket_id, key);
            ''')
    
    @contextmanager
    def _get_connection(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()
    
    def create_bucket(self, bucket_name):
        with self._get_connection() as conn:
            now = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S.000Z')
            conn.execute(
                'INSERT OR IGNORE INTO buckets (name, created_at) VALUES (?, ?)',
                (bucket_name, now)
            )
    
    def delete_bucket(self, bucket_name):
        with self._get_connection() as conn:
            bucket_id = conn.execute(
                'SELECT id FROM buckets WHERE name = ?',
                (bucket_name,)
            ).fetchone()
            
            if not bucket_id:
                return False
                
            # Check if bucket is empty
            count = conn.execute(
                'SELECT COUNT(*) FROM objects WHERE bucket_id = ?',
                (bucket_id['id'],)
            ).fetchone()[0]
            
            if count > 0:
                return False
                
            conn.execute('DELETE FROM buckets WHERE id = ?', (bucket_id['id'],))
            return True
    
    def get_object(self, bucket_name, key):
        with self._get_connection() as conn:
            return conn.execute('''
                SELECT o.* FROM objects o
                JOIN buckets b ON b.id = o.bucket_id
                WHERE b.name = ? AND o.key = ?
            ''', (bucket_name, key)).fetchone()
    
    def list_objects(self, bucket_name, prefix='', max_keys=1000):
        with self._get_connection() as conn:
            return conn.execute('''
                SELECT o.* FROM objects o
                JOIN buckets b ON b.id = o.bucket_id
                WHERE b.name = ? AND o.key LIKE ?
                LIMIT ?
            ''', (bucket_name, f'{prefix}%', max_keys)).fetchall()
    
    def put_object(self, bucket_name, key, size, content_type, md5, storage_path, created_at=None, modified_at=None):
        with self._get_connection() as conn:
            bucket_id = conn.execute(
                'SELECT id FROM buckets WHERE name = ?',
                (bucket_name,)
            ).fetchone()
            
            if not bucket_id:
                return False
                
            if created_at is None or modified_at is None:
                now = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S.000Z')
                created_at = created_at or now
                modified_at = modified_at or now
                
            conn.execute('''
                INSERT OR REPLACE INTO objects 
                (bucket_id, key, size, content_type, md5, storage_path, created_at, modified_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (bucket_id['id'], key, size, content_type, md5, storage_path, created_at, modified_at))
            return True
    
    def delete_object(self, bucket_name, key):
        with self._get_connection() as conn:
            result = conn.execute('''
                DELETE FROM objects 
                WHERE bucket_id = (SELECT id FROM buckets WHERE name = ?)
                AND key = ?
            ''', (bucket_name, key))
            return result.rowcount > 0

    def _get_bucket_id(self, bucket_name):
        """Get bucket ID from name"""
        with self._get_connection() as conn:
            result = conn.execute(
                'SELECT id FROM buckets WHERE name = ?',
                (bucket_name,)
            ).fetchone()
            return result['id'] if result else None

    def _drop_tables(self):
        """Drop all tables"""
        with self._get_connection() as conn:
            conn.executescript('''
                DROP TABLE IF EXISTS objects;
                DROP TABLE IF EXISTS buckets;
            ''')

    def _create_tables(self):
        """Create all tables"""
        self._init_db() 