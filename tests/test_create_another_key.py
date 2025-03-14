from boto.s3.key import Key

def test_create_another_key(bucket):
    kwrite = Key(bucket)
    kwrite.key = 'goodbye.txt'
    kwrite.set_contents_from_string('Nothing to see here, goodbye')

    kread = Key(bucket)
    kread.key = 'goodbye.txt'
    content = kread.get_contents_as_string()

    assert content == b'Nothing to see here, goodbye' 