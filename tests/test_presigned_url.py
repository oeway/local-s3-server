"""Test presigned URL functionality."""

import os
import time
import pytest
import requests
import boto3
from botocore.client import Config

@pytest.fixture(scope="function")
def s3_client(s3_connection):
    """Fixture that provides a boto3 S3 client configured for the test server."""
    host = s3_connection.host
    port = s3_connection.port
    
    return boto3.client(
        's3',
        endpoint_url=f"http://{host}:{port}",
        aws_access_key_id="test",
        aws_secret_access_key="test",
        region_name='us-east-1',
        config=Config(
            signature_version='s3v4',  # Use SigV4 (modern version)
            s3={'addressing_style': 'path'}  # Use path-style addressing
        )
    )

def test_presigned_url_get(s3_client, bucket):
    """Test generating and using a presigned URL for GET."""
    # Create test data
    key = "test_presigned.txt"
    content = b"Hello from presigned URL!"
    s3_client.put_object(Bucket=bucket.name, Key=key, Body=content)
    
    # Generate presigned URL using boto3
    url = s3_client.generate_presigned_url(
        'get_object',
        Params={'Bucket': bucket.name, 'Key': key},
        ExpiresIn=3600
    )

    # Use presigned URL to get object
    response = requests.get(url)
    assert response.status_code == 200
    assert response.content == content

def test_presigned_url_put(s3_client, bucket):
    """Test generating and using a presigned URL for PUT."""
    key = "test_presigned_put.txt"
    content = b"Uploaded via presigned URL!"
    
    # Generate presigned URL for PUT
    url = s3_client.generate_presigned_url(
        'put_object',
        Params={'Bucket': bucket.name, 'Key': key},
        ExpiresIn=3600
    )

    # Use presigned URL to put object
    response = requests.put(url, data=content)
    assert response.status_code == 200
    
    # Verify the object was created
    response = s3_client.get_object(Bucket=bucket.name, Key=key)
    assert response['Body'].read() == content

def test_presigned_url_expiry(s3_client, bucket):
    """Test presigned URL expiration."""
    key = "test_presigned_expiry.txt"
    content = b"This URL will expire quickly!"
    s3_client.put_object(Bucket=bucket.name, Key=key, Body=content)
    
    # Generate presigned URL with short expiry
    url = s3_client.generate_presigned_url(
        'get_object',
        Params={'Bucket': bucket.name, 'Key': key},
        ExpiresIn=1  # 1 second expiry
    )

    # Wait for URL to expire
    time.sleep(2)
    
    # Try to use expired URL
    response = requests.get(url)
    assert response.status_code == 401  # Unauthorized is returned for expired URLs

def test_presigned_url_invalid_signature(s3_client, bucket):
    """Test presigned URL with tampered signature."""
    key = "test_presigned_invalid.txt"
    content = b"This URL will be tampered with!"
    s3_client.put_object(Bucket=bucket.name, Key=key, Body=content)
    
    # Generate presigned URL
    url = s3_client.generate_presigned_url(
        'get_object',
        Params={'Bucket': bucket.name, 'Key': key},
        ExpiresIn=3600
    )

    # Tamper with the signature
    tampered_url = url.replace("Signature=", "Signature=invalid")
    
    # Try to use tampered URL
    response = requests.get(tampered_url)
    assert response.status_code == 401  # Unauthorized is returned for invalid signatures 