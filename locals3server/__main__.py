"""Main entry point for running local-s3-server as a module.

This allows running the server using:
    python -m locals3server
"""

import sys
import argparse
import os

from .fastapi_server import run_server

def main():
    parser = argparse.ArgumentParser(description='A local S3-compatible server.')
    parser.add_argument('--hostname', dest='hostname', action='store',
                        default='localhost',
                        help='Hostname to listen on, defaults to localhost, use 0.0.0.0 to listen on all interfaces')
    parser.add_argument('--port', dest='port', action='store',
                        default=10001, type=int,
                        help='Port to run server on.')
    parser.add_argument('--root-dir', dest='root_dir', action='store',
                        default='./s3store',
                        help='Defaults to ./s3store.')
    parser.add_argument('--pull-from-aws', dest='pull_from_aws', action='store_true',
                        default=False,
                        help='Pull non-existent keys from aws.')
    parser.add_argument('--access-key-id', dest='access_key_id', action='store',
                        default='test',
                        help='AWS access key ID (default: test)')
    parser.add_argument('--secret-access-key', dest='secret_access_key', action='store',
                        default='test',
                        help='AWS secret access key (default: test)')
    args = parser.parse_args()

    print('Starting server, use <Ctrl-C> to stop')
    run_server(
        hostname=args.hostname,
        port=args.port,
        root=args.root_dir,
        pull_from_aws=args.pull_from_aws,
        access_key_id=args.access_key_id,
        secret_access_key=args.secret_access_key
    )
    return 0

if __name__ == '__main__':
    sys.exit(main()) 