def test_image_copy(s3_connection, bucket):
    # Create a source key in the fixture bucket
    source_key = bucket.new_key('pics/example.jpg')
    source_key.set_contents_from_string('test image content')
    
    # Create destination bucket
    dst_bucket_name = f'backup-{bucket.name}'
    dst_bucket = s3_connection.create_bucket(dst_bucket_name)
    
    try:
        # Get the source key content
        content = source_key.get_contents_as_string()
        
        # Create and set the destination key
        dst_key = dst_bucket.new_key('pics/example.jpg')
        dst_key.set_contents_from_string(content)
        
        # Verify the copy
        copied_key = dst_bucket.get_key('pics/example.jpg')
        assert copied_key is not None
        assert copied_key.get_contents_as_string() == b'test image content'
    
    finally:
        # Cleanup
        for key in dst_bucket.list():
            dst_bucket.delete_key(key)
        s3_connection.delete_bucket(dst_bucket_name) 