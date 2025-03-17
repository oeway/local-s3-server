import os
import pytest
import uvicorn
import multiprocessing
from pathlib import Path
import boto.s3.connection
from boto.s3.connection import OrdinaryCallingFormat
import threading
import time
import tempfile
from typing import Generator
import socket
import shutil

import boto
from boto.s3.connection import S3Connection
from locals3server.file_store import FileStore
from locals3server.fastapi_server import app, config, file_store

def run_server(host, port, storage_dir):
    """Run the server in a separate process"""
    # Ensure storage directory exists
    os.makedirs(storage_dir, exist_ok=True)
    
    # Configure the server
    config["hostname"] = host
    config["port"] = port
    config["root"] = str(storage_dir)
    config["access_key_id"] = "test"
    config["secret_access_key"] = "test"
    
    # Run the server
    uvicorn.run(app, host=host, port=port)

def find_free_port():
    """Find a free port to use for the server"""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('', 0))
        s.listen(1)
        port = s.getsockname()[1]
    return port

@pytest.fixture(scope="function")
def s3_connection() -> Generator[S3Connection, None, None]:
    """
    Fixture that creates a connection to the mock S3 server
    """
    host = "127.0.0.1"
    port = find_free_port()
    
    # Create a temporary directory for storage
    storage_dir = tempfile.mkdtemp()
    
    # Start server in a separate process
    server_process = multiprocessing.Process(
        target=run_server,
        args=(host, port, storage_dir),
        daemon=True
    )
    server_process.start()
    
    # Wait for server to start
    time.sleep(2)
    
    # Create connection with proper authentication
    conn = S3Connection(
        aws_access_key_id="test",
        aws_secret_access_key="test",
        is_secure=False,
        port=port,
        host=host,
        calling_format=boto.s3.connection.OrdinaryCallingFormat(),
    )
    
    # Create and expose the file_store instance
    fs = FileStore(storage_dir)
    conn.file_store = fs
    
    yield conn
    
    # Cleanup
    server_process.terminate()
    server_process.join(timeout=1)
    
    try:
        shutil.rmtree(storage_dir)
    except OSError:
        pass

@pytest.fixture(scope="function")
def bucket(s3_connection):
    """
    Fixture that creates a test bucket and cleans it up after
    """
    bucket_name = "test-bucket"
    bucket = s3_connection.create_bucket(bucket_name)
    yield bucket
    try:
        for key in bucket.list():
            key.delete()
        bucket.delete()
    except:
        pass 