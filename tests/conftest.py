import os
import pytest
import uvicorn
import multiprocessing
from pathlib import Path
from locals3server.fastapi_server import app, config
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

def run_server(host, port, storage_dir):
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

@pytest.fixture(scope="session")
def test_server():
    """
    Fixture that starts the S3 server for testing and cleans up after
    """
    # Test server configuration
    host = "127.0.0.1"
    port = 10001  # Use the default port from fastapi_server
    storage_dir = Path("test_storage").absolute()  # Use absolute path
    
    # Start server in a separate process
    server_process = multiprocessing.Process(
        target=run_server,
        args=(host, port, storage_dir)
    )
    server_process.start()
    
    # Wait a moment for server to start
    time.sleep(1)
    
    # Provide the server details to the test
    yield {
        "host": host,
        "port": port,
        "endpoint_url": f"http://{host}:{port}",
        "storage_dir": storage_dir,
        "access_key_id": config["access_key_id"],
        "secret_access_key": config["secret_access_key"]
    }
    
    # Cleanup
    server_process.terminate()
    server_process.join()
    
    # Clean up storage directory
    if storage_dir.exists():
        shutil.rmtree(storage_dir)

def find_free_port():
    """Find a free port to use for the server"""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('', 0))
        s.listen(1)
        port = s.getsockname()[1]
    return port

def run_server_thread(host, port, storage_dir):
    """Run the server in a thread with proper configuration"""
    # Update server configuration
    config["hostname"] = host
    config["port"] = port
    config["root"] = storage_dir
    config["access_key_id"] = "test"
    config["secret_access_key"] = "test"
    
    # Initialize file store
    global file_store
    file_store = FileStore(storage_dir)
    
    # Run server
    import uvicorn
    uvicorn.run(app, host=host, port=port)

@pytest.fixture(scope="function")
def s3_connection() -> Generator[S3Connection, None, None]:
    """
    Fixture that creates a connection to the mock S3 server
    """
    host = "127.0.0.1"
    port = find_free_port()
    
    # Create a temporary directory for storage
    storage_dir = tempfile.mkdtemp()
    
    # Create and expose the file_store instance
    file_store = FileStore(storage_dir)
    
    # Update server configuration and set the file_store instance
    config["hostname"] = host
    config["port"] = port
    config["root"] = storage_dir
    config["access_key_id"] = "test"
    config["secret_access_key"] = "test"
    app.state.file_store = file_store  # Set the file_store instance in the app state
    
    # Start server in a separate thread
    server_thread = threading.Thread(
        target=uvicorn.run,
        args=(app,),
        kwargs={
            "host": host,
            "port": port
        },
        daemon=True
    )
    server_thread.start()
    
    # Wait for server to start
    time.sleep(1)
    
    # Create connection with proper authentication
    conn = S3Connection(
        aws_access_key_id="test",
        aws_secret_access_key="test",
        is_secure=False,
        port=port,
        host=host,
        calling_format=boto.s3.connection.OrdinaryCallingFormat(),
    )
    
    # Expose file_store instance
    conn.file_store = file_store
    
    yield conn
    
    # Cleanup
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