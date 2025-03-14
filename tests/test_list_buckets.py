import os
import boto
from boto.s3.connection import OrdinaryCallingFormat

def test_list_buckets(s3_connection, bucket):
    # Create a new connection using the same credentials as the fixture
    s3_with_creds = boto.connect_s3(
        aws_access_key_id="test",
        aws_secret_access_key="test",
        host='localhost',
        port=10001,
        calling_format=OrdinaryCallingFormat(),
        is_secure=False
    )
    
    # Create a bucket using the fixture
    buckets = s3_with_creds.get_all_buckets()
    
    # Verify that at least one bucket exists (the one created by fixture)
    assert len(buckets) > 0
    
    # Verify that our fixture bucket is in the list
    bucket_names = [b.name for b in buckets]
    assert bucket.name in bucket_names 