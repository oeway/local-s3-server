from boto.s3.key import Key

def test_create_nested(bucket):
    nested_key = 'level1/level2/level3/nested.txt'
    kwrite = Key(bucket)
    kwrite.key = nested_key
    kwrite.set_contents_from_string('Nothing to see here, nested')

    kread = Key(bucket)
    kread.key = nested_key
    content = kread.get_contents_as_string()

    assert content == b'Nothing to see here, nested' 