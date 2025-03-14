import pytest
import boto
from boto.s3.connection import OrdinaryCallingFormat
import uuid

@pytest.fixture(scope='session')
def s3_connection():
    return boto.connect_s3(
        host='localhost',
        port=10001,
        calling_format=OrdinaryCallingFormat(),
        is_secure=False
    )

@pytest.fixture
def bucket(s3_connection):
    bucket_name = f'mocking-{uuid.uuid4()}'
    bucket = s3_connection.create_bucket(bucket_name)
    yield bucket
    # Cleanup after test
    for key in bucket.list():
        bucket.delete_key(key)
    s3_connection.delete_bucket(bucket_name) 