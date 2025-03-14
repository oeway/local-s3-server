import os
import pytest
import uvicorn
import multiprocessing
from pathlib import Path
from locals3server.fastapi_server import app, config
import boto.s3.connection
from boto.s3.connection import OrdinaryCallingFormat

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
    import time
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
        import shutil
        shutil.rmtree(storage_dir)

@pytest.fixture(scope="function")
def s3_connection(test_server):
    """
    Fixture that provides a boto S3 connection configured to talk to the test server
    """
    conn = boto.s3.connection.S3Connection(
        aws_access_key_id=test_server["access_key_id"],
        aws_secret_access_key=test_server["secret_access_key"],
        is_secure=False,
        host=test_server["host"],
        port=test_server["port"],
        calling_format=OrdinaryCallingFormat()
    )
    return conn

@pytest.fixture(scope="function")
def bucket(s3_connection):
    """
    Fixture that creates a test bucket and cleans it up after
    """
    bucket_name = "test-bucket"
    bucket = s3_connection.create_bucket(bucket_name)
    yield bucket
    
    # Clean up all objects in the bucket
    for key in bucket.list():
        key.delete()
    
    # Delete the bucket
    bucket.delete() 