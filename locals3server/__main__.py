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
                        help='Hostname to listen on.')
    parser.add_argument('--port', dest='port', action='store',
                        default=10001, type=int,
                        help='Port to run server on.')
    parser.add_argument('--root', dest='root', action='store',
                        default='%s/s3store' % os.environ['HOME'],
                        help='Defaults to $HOME/s3store.')
    parser.add_argument('--pull-from-aws', dest='pull_from_aws', action='store_true',
                        default=False,
                        help='Pull non-existent keys from aws.')
    args = parser.parse_args()

    print('Starting server, use <Ctrl-C> to stop')
    run_server(
        hostname=args.hostname,
        port=args.port,
        root=args.root,
        pull_from_aws=args.pull_from_aws
    )
    return 0

if __name__ == '__main__':
    sys.exit(main()) 