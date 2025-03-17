"""Test the __main__ module."""

import sys
import pytest
from unittest.mock import patch
from locals3server.__main__ import main

def test_main_args():
    """Test the main function with command line arguments."""
    test_args = [
        '--hostname', '0.0.0.0',
        '--port', '8000',
        '--root-dir', '/tmp/s3store',
        '--access-key-id', 'testkey',
        '--secret-access-key', 'testsecret'
    ]
    
    with patch.object(sys, 'argv', ['locals3server'] + test_args):
        with patch('locals3server.__main__.run_server') as mock_run_server:
            main()
            
            # Check that run_server was called with the correct arguments
            mock_run_server.assert_called_once_with(
                hostname='0.0.0.0',
                port=8000,
                root='/tmp/s3store',
                pull_from_aws=False,
                access_key_id='testkey',
                secret_access_key='testsecret'
            )

def test_main_defaults():
    """Test the main function with default values."""
    with patch.object(sys, 'argv', ['locals3server']):
        with patch('locals3server.__main__.run_server') as mock_run_server:
            main()
            
            # Check that run_server was called with the default arguments
            mock_run_server.assert_called_once_with(
                hostname='localhost',
                port=10001,
                root='./s3store',
                pull_from_aws=False,
                access_key_id='test',
                secret_access_key='test'
            ) 