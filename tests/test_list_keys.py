"""Test listing keys functionality."""
from boto.s3.key import Key

def test_list_keys(s3_connection, bucket):
    """Test listing keys in a bucket."""
    # Create test keys
    test_keys = ['test1.txt', 'test2.txt', 'folder/test3.txt']
    content = b'test content'
    
    # Put objects
    for key_name in test_keys:
        k = Key(bucket)
        k.key = key_name
        k.set_contents_from_string(content)
    
    # List objects
    all_keys = bucket.list()
    
    # Get list of keys
    listed_keys = [k.name for k in all_keys]
    
    # Verify all test keys are present
    for key in test_keys:
        assert key in listed_keys
    
    # Test prefix filtering
    folder_keys = bucket.list(prefix='folder/')
    folder_key_names = [k.name for k in folder_keys]
    assert len(folder_key_names) == 1
    assert folder_key_names[0] == 'folder/test3.txt' 