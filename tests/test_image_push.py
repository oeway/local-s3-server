import os
from boto.s3.key import Key

def test_image_push(s3_connection, bucket, tmp_path):
    # Create a test image file
    test_image_path = tmp_path / "example.jpg"
    test_image_content = b"test image content"
    test_image_path.write_bytes(test_image_content)
    
    # Create and push the key
    k_img = Key(bucket)
    k_img.key = 'pics/example.jpg'
    k_img.set_contents_from_filename(str(test_image_path))
    
    # Verify the upload
    uploaded_key = bucket.get_key('pics/example.jpg')
    assert uploaded_key is not None
    assert uploaded_key.get_contents_as_string() == test_image_content 