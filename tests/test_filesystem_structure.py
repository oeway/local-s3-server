import os
import shutil
from boto.s3.key import Key
import pytest
import urllib.parse
import re

def test_file_structure(s3_connection, bucket):
    """Test that files are stored with original names and paths"""
    # Create a nested directory structure
    files_to_create = {
        'file1.txt': 'Content 1',
        'folder1/file2.txt': 'Content 2',
        'folder1/subfolder/file3.txt': 'Content 3',
        'folder2/file4.txt': 'Content 4'
    }
    
    # Upload files
    for path, content in files_to_create.items():
        k = Key(bucket)
        k.key = path
        k.set_contents_from_string(content)
    
    # Verify filesystem structure
    bucket_path = os.path.join(s3_connection.file_store.root, bucket.name)
    assert os.path.exists(bucket_path)
    
    # Check each file exists with correct content and structure
    for path, content in files_to_create.items():
        file_path = os.path.join(bucket_path, path)
        assert os.path.exists(file_path)
        with open(file_path, 'r') as f:
            assert f.read() == content

def test_existing_files_import(s3_connection):
    """Test that existing files in a directory are properly imported"""
    # Create a test directory structure
    test_bucket = "test-existing-bucket"
    bucket_path = os.path.join(s3_connection.file_store.root, test_bucket)
    os.makedirs(bucket_path, exist_ok=True)
    
    # Create some test files
    test_files = {
        'existing1.txt': 'Existing Content 1',
        'folder/existing2.txt': 'Existing Content 2',
        'folder/subfolder/existing3.txt': 'Existing Content 3'
    }
    
    # Create files in filesystem
    for path, content in test_files.items():
        file_path = os.path.join(bucket_path, path)
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        with open(file_path, 'w') as f:
            f.write(content)
    
    try:
        # Force database rebuild
        s3_connection.file_store._rebuild_database()
        
        # Get bucket through S3
        bucket = s3_connection.get_bucket(test_bucket)
        
        # Verify all files are listed and accessible
        for path, content in test_files.items():
            k = bucket.get_key(path)
            assert k is not None
            assert k.get_contents_as_string().decode() == content
            
            # Verify file still exists in original location
            file_path = os.path.join(bucket_path, path)
            assert os.path.exists(file_path)
            with open(file_path, 'r') as f:
                assert f.read() == content
    
    finally:
        # Cleanup
        if os.path.exists(bucket_path):
            shutil.rmtree(bucket_path)

def test_file_modifications(s3_connection, bucket):
    """Test that files can be modified both through S3 and filesystem"""
    # Create initial file through S3
    k = Key(bucket)
    k.key = 'test.txt'
    k.set_contents_from_string('Initial content')
    
    # Modify file through filesystem
    file_path = os.path.join(s3_connection.file_store.root, bucket.name, 'test.txt')
    with open(file_path, 'w') as f:
        f.write('Modified content')
    
    # Force database rebuild to detect changes
    s3_connection.file_store._rebuild_database()
    
    # Verify changes are reflected in S3
    k = bucket.get_key('test.txt')
    assert k is not None
    assert k.get_contents_as_string().decode() == 'Modified content'

def test_special_characters(s3_connection, bucket):
    """Test that special characters in filenames are rejected"""
    # Test valid filenames
    valid_files = {
        'normal-file.txt': 'Content 1',
        'file_with_underscore.txt': 'Content 2',
        'folder/nested/file.txt': 'Content 3',
        'path/with-hyphens/file.txt': 'Content 4'
    }
    
    # Upload and verify valid files
    for path, content in valid_files.items():
        k = Key(bucket)
        k.key = path
        k.set_contents_from_string(content)
        
        # Verify file exists and content is correct
        k = bucket.get_key(path)
        assert k is not None
        assert k.get_contents_as_string().decode() == content
    
    # Test invalid filenames
    invalid_files = [
        'file with spaces.txt',
        'file_with_symbols!@#$%.txt',
        'folder with spaces/file.txt',
        'path/with/special_#@/file.txt'
    ]
    
    # Attempt to upload invalid files and verify they are rejected
    for path in invalid_files:
        k = Key(bucket)
        k.key = path
        try:
            k.set_contents_from_string('Invalid content')
            assert False, f"Expected error for {path}"
        except Exception as e:
            # The server should return a 400 error with InvalidKeyName
            error_str = str(e)
            assert "400" in error_str or "InvalidKeyName" in error_str or "invalid characters" in error_str 