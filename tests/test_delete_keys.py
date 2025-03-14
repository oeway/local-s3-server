from boto.s3.key import Key

def test_delete_keys(bucket):
    keys_to_create = ['hello.txt', 'goodbye.txt']
    for key_name in keys_to_create:
        kwrite = Key(bucket)
        kwrite.key = key_name
        kwrite.set_contents_from_string('Temporary content')

    bucket.delete_keys(keys_to_create)

    for key_name in keys_to_create:
        assert bucket.get_key(key_name) is None 