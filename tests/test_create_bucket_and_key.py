import pytest
from boto.s3.key import Key

def test_create_bucket_and_key(bucket):
    kwrite = Key(bucket)
    kwrite.key = 'hello.txt'
    kwrite.set_contents_from_string('Nothing to see here, hello')

    kread = Key(bucket)
    kread.key = 'hello.txt'
    content = kread.get_contents_as_string()

    assert content == b'Nothing to see here, hello' 