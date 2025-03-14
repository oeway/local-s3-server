# FastS3

A lightweight, FastAPI-based S3-compatible server designed for local development and testing. Perfect for developing and testing S3-dependent applications without connecting to actual AWS services.

## Features

- S3-compatible API implementation
- Local storage for S3 buckets and objects
- FastAPI-powered for modern async support
- Simple configuration and setup
- Perfect for testing and development environments
- No AWS account required

## Installation

```bash
pip install fasts3
```

## Quick Start

1. Create a fake credentials file (`fake_credentials`):
```ini
AWSAccessKeyId=12345
AWSSecretKey=12345
```

2. Set the credentials environment variable:
```bash
export AWS_CREDENTIAL_FILE="path/to/fake_credentials"
```

3. Start the server:
```bash
python -m fasts3
```

4. Use with any S3 client by pointing to the local endpoint:
```python
import boto3

s3 = boto3.client('s3',
    endpoint_url='http://localhost:10001',
    aws_access_key_id='12345',
    aws_secret_access_key='12345'
)
```

## Configuration

The server can be configured using environment variables:

- `FASTS3_HOST`: Host to bind (default: localhost)
- `FASTS3_PORT`: Port to listen on (default: 10001)
- `FASTS3_STORAGE`: Storage directory (default: ~/.fasts3)

## Examples

The `examples` directory contains sample code for common operations:

- Creating buckets and objects
- Uploading and downloading files
- Listing buckets and objects
- Deleting objects
- Working with nested paths
- Image handling

See the [examples directory](./examples) for complete examples.

## Development

To set up the development environment:

```bash
git clone https://github.com/yourusername/fasts3.git
cd fasts3
pip install -e ".[dev]"
pytest
```

## Attribution

This project is a modernized fork of PyS3Local, which itself was derived from mock-s3 (a Python port of Fake-S3). The codebase has been significantly enhanced with FastAPI integration and modern Python practices.
