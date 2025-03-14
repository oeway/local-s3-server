from boto.s3.key import Key

def test_key_list(s3_connection, bucket):
    # Create some test keys
    test_keys = [
        ('level1/key1.txt', 'content1'),
        ('level2/key2.txt', 'content2'),
        ('other/key3.txt', 'content3'),
        ('level3/key4.txt', 'content4'),
    ]
    
    for key_name, content in test_keys:
        k = Key(bucket)
        k.key = key_name
        k.set_contents_from_string(content)
    
    # Test prefix filtering
    level_keys = bucket.get_all_keys(prefix='level')
    assert len(level_keys) == 3
    assert all(k.name.startswith('level') for k in level_keys)
    
    # Test max_keys parameter
    limited_keys = bucket.get_all_keys(max_keys=2)
    assert len(limited_keys) == 2 