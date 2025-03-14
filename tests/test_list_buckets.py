import os
import boto
from boto.s3.connection import OrdinaryCallingFormat

def test_list_buckets(s3_connection, bucket):
    # Point boto to our fake credentials file
    os.environ['AWS_CREDENTIAL_FILE'] = os.path.join(os.path.dirname(__file__), 'fake_credentials')
    
    # Create a new connection using the fake credentials
    s3_with_creds = boto.connect_s3(
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
    
    # Clean up environment
    del os.environ['AWS_CREDENTIAL_FILE'] 