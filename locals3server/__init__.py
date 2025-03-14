"""local-s3-server - A lightweight S3-compatible server for local development and testing.

This module provides a local S3-compatible server for development and testing.
"""

__version__ = '0.1'

# Import from the FastAPI implementation
from .fastapi_server import run_server, app

# For backwards compatibility
from .main import main as legacy_main
from .main import ThreadedHTTPServer, S3Handler

