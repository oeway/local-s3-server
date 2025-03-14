from boto.s3.key import Key

def test_delete_key(bucket):
    key_name = 'hello.txt'
    kwrite = Key(bucket)
    kwrite.key = key_name
    kwrite.set_contents_from_string('Temporary content')

    bucket.delete_key(key_name)

    assert bucket.get_key(key_name) is None 