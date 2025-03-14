"""
FastAPI implementation of the S3 mock server.
This provides a more robust and modern implementation with better error handling and async support.
"""

import os
import logging
from typing import Dict, List, Optional, Union
import xml.etree.ElementTree as ET
from datetime import datetime

import uvicorn
from fastapi import FastAPI, Request, Response, Header, HTTPException, Depends
from fastapi.responses import StreamingResponse
from starlette.datastructures import Headers

from .file_store import FileStore
from . import xml_templates

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="local-s3-server",
    description="A lightweight S3-compatible server for local development and testing"
)

# Global configuration
config = {
    "hostname": "localhost",
    "port": 10001,
    "root": f"{os.environ['HOME']}/s3store",
    "pull_from_aws": False
}

# Initialize file store
file_store = None


def get_file_store():
    """Dependency to get the file store instance."""
    global file_store
    if file_store is None:
        file_store = FileStore(config["root"])
    return file_store


def parse_bucket_and_key(request: Request) -> tuple:
    """Parse bucket name and key from the request path."""
    path = request.url.path
    host = request.headers.get('host', '').split(':')[0]
    bucket_name = None
    item_name = None
    
    # Virtual host style: bucket.localhost:10001
    if host != config["hostname"] and config["hostname"] in host:
        idx = host.index(config["hostname"])
        bucket_name = host[:idx-1]
        item_name = path.strip('/')
    # Path style: localhost:10001/bucket/key
    else:
        parts = path.strip('/').split('/', 1)
        bucket_name = parts[0] if parts else None
        item_name = parts[1] if len(parts) > 1 else None
        
        # Handle case where bucket name is in the path
        if not bucket_name and path.startswith('/'):
            bucket_name = path.strip('/')
    
    return bucket_name, item_name


@app.get("/{path:path}")
async def get_handler(request: Request, path: str, file_store: FileStore = Depends(get_file_store)):
    """Handle GET requests for listing buckets, bucket contents, and retrieving objects."""
    bucket_name, item_name = parse_bucket_and_key(request)
    
    # List buckets if no bucket specified
    if not bucket_name:
        return list_buckets_handler(file_store)
    
    # List bucket contents if no key specified
    if not item_name:
        return list_bucket_handler(request, bucket_name, file_store)
    
    # Check for ACL request
    query_params = dict(request.query_params)
    if 'acl' in query_params:
        return get_acl_handler()
    
    # Get item
    return get_item_handler(bucket_name, item_name, file_store)


@app.get("/")
async def root(request: Request, file_store: FileStore = Depends(get_file_store)):
    """Handle GET requests to the root path."""
    return await get_handler(request, "", file_store)


@app.head("/{path:path}")
async def head_handler(request: Request, path: str, file_store: FileStore = Depends(get_file_store)):
    """Handle HEAD requests for checking object existence."""
    bucket_name, item_name = parse_bucket_and_key(request)
    
    if not bucket_name:
        return Response(status_code=400, content="", media_type="text/xml")
    
    if not item_name:
        # Check bucket existence
        bucket = file_store.get_bucket(bucket_name)
        if not bucket:
            return Response(status_code=404, content="", media_type="text/xml")
        return Response(status_code=200, content="", media_type="text/xml")
    
    # Check object existence
    item = file_store.get_item(bucket_name, item_name)
    if not item:
        return Response(status_code=404, content="", media_type="text/xml")
    
    # Set up response headers
    headers = {}
    
    # Format last modified date
    if hasattr(item, 'creation_date'):
        last_modified = item.creation_date
    else:
        last_modified = item.modified_date
    last_modified_dt = datetime.strptime(last_modified, '%Y-%m-%dT%H:%M:%S.000Z')
    last_modified = last_modified_dt.strftime('%a, %d %b %Y %H:%M:%S GMT')
    
    headers["Last-Modified"] = last_modified
    headers["Etag"] = f'"{item.md5}"'
    headers["Accept-Ranges"] = "bytes"
    headers["Content-Type"] = item.content_type
    headers["Content-Length"] = str(item.size)
    
    return Response(status_code=200, content="", headers=headers, media_type=item.content_type)


@app.put("/{path:path}")
async def put_handler(
    request: Request, 
    path: str, 
    file_store: FileStore = Depends(get_file_store)
):
    """Handle PUT requests for creating buckets and storing objects."""
    bucket_name, item_name = parse_bucket_and_key(request)
    
    # No bucket name provided
    if not bucket_name:
        raise HTTPException(status_code=400, detail="Bucket name is required")
    
    # Create bucket if no key provided
    if not item_name:
        bucket = file_store.create_bucket(bucket_name)
        return Response(status_code=200, content="", media_type="text/xml")
    
    # Check for ACL request
    query_params = dict(request.query_params)
    if 'acl' in query_params:
        # Set ACL (not implemented in detail)
        return Response(status_code=200, content="", media_type="text/xml")
    
    # Check for copy request
    copy_source = request.headers.get('x-amz-copy-source')
    if copy_source:
        src_bucket, sep, src_key = copy_source.partition('/')
        file_store.copy_item(src_bucket, src_key, bucket_name, item_name, request)
        return Response(status_code=200, content="", media_type="text/xml")
    
    # Store item
    bucket = file_store.get_bucket(bucket_name)
    if not bucket:
        bucket = file_store.create_bucket(bucket_name)
    
    # Read request body
    body = await request.body()
    
    # Create headers dict from request headers
    headers = {}
    for key, value in request.headers.items():
        headers[key.lower()] = value
    
    # Store the item
    item = file_store.store_data(bucket, item_name, headers, body)
    
    # Return response
    headers = {"Etag": f'"{item.md5}"', "Content-Type": "text/xml"}
    return Response(status_code=200, content="", headers=headers)


@app.delete("/{path:path}")
async def delete_handler(
    request: Request, 
    path: str, 
    file_store: FileStore = Depends(get_file_store)
):
    """Handle DELETE requests for removing objects and buckets."""
    bucket_name, item_name = parse_bucket_and_key(request)
    
    # Handle bucket deletion when bucket name is in the path
    if not bucket_name and path:
        bucket_name = path.strip('/')
        item_name = None
    
    if not bucket_name:
        return Response(status_code=400, content="", media_type="text/xml")
    
    # Delete object if item_name is provided
    if item_name:
        file_store.delete_item(bucket_name, item_name)
        return Response(status_code=204)
    
    # Delete bucket if no item_name
    try:
        file_store.delete_bucket(bucket_name)
        return Response(status_code=204)
    except Exception as e:
        if "BucketNotEmpty" in str(e):
            return Response(
                status_code=409,
                content="BucketNotEmpty: The bucket you tried to delete is not empty",
                media_type="text/xml"
            )
        return Response(
            status_code=404,
            content=f"NoSuchBucket: The specified bucket {bucket_name} does not exist",
            media_type="text/xml"
        )


@app.post("/{path:path}")
async def post_handler(
    request: Request, 
    path: str, 
    file_store: FileStore = Depends(get_file_store)
):
    """Handle POST requests, primarily for multi-delete operations."""
    bucket_name, item_name = parse_bucket_and_key(request)
    query_params = dict(request.query_params)
    
    # Handle delete_keys operation
    if 'delete' in query_params:
        body = await request.body()
        root = ET.fromstring(body)
        keys = []
        for obj in root.findall('Object'):
            keys.append(obj.find('Key').text)
        
        # Delete the keys
        for key in keys:
            file_store.delete_item(bucket_name, key)
        
        # Generate response XML
        xml = ''
        for key in keys:
            xml += xml_templates.deleted_deleted_xml.format(key=key)
        xml = xml_templates.deleted_xml.format(contents=xml)
        
        return Response(
            content=xml.encode('utf-8'),
            media_type="application/xml",
            status_code=200
        )
    
    # Default response for unhandled POST requests
    return Response(
        content=f"{None}: [{bucket_name}] {item_name}".encode('utf-8'),
        status_code=400
    )


def list_buckets_handler(file_store: FileStore):
    """Handle listing all buckets."""
    buckets = file_store.buckets
    xml = ''
    for bucket in buckets:
        xml += xml_templates.buckets_bucket_xml.format(bucket=bucket)
    xml = xml_templates.buckets_xml.format(buckets=xml)
    
    return Response(
        content=xml.encode('utf-8'),
        media_type="application/xml",
        status_code=200
    )


def list_bucket_handler(request: Request, bucket_name: str, file_store: FileStore):
    """Handle listing contents of a bucket."""
    bucket = file_store.get_bucket(bucket_name)
    if not bucket:
        xml = xml_templates.error_no_such_bucket_xml.format(name=bucket_name)
        return Response(
            content=xml.encode('utf-8'),
            media_type="application/xml",
            status_code=404
        )
    
    # Parse query parameters
    query_params = dict(request.query_params)
    kwargs = {
        'marker': query_params.get('marker', [''])[0] if isinstance(query_params.get('marker'), list) else query_params.get('marker', ''),
        'prefix': query_params.get('prefix', [''])[0] if isinstance(query_params.get('prefix'), list) else query_params.get('prefix', ''),
        'max_keys': query_params.get('max-keys', ['1000'])[0] if isinstance(query_params.get('max-keys'), list) else query_params.get('max-keys', '1000'),
        'delimiter': query_params.get('delimiter', [''])[0] if isinstance(query_params.get('delimiter'), list) else query_params.get('delimiter', ''),
    }
    
    # Get bucket contents
    bucket_query = file_store.get_all_keys(bucket, **kwargs)
    
    # Generate response XML
    contents = ''
    for s3_item in bucket_query.matches:
        contents += xml_templates.bucket_query_content_xml.format(s3_item=s3_item)
    xml = xml_templates.bucket_query_xml.format(bucket_query=bucket_query, contents=contents)
    
    return Response(
        content=xml.encode('utf-8'),
        media_type="application/xml",
        status_code=200
    )


def get_acl_handler():
    """Handle ACL requests."""
    return Response(
        content=xml_templates.acl_xml.encode('utf-8'),
        media_type="application/xml",
        status_code=200
    )


def get_item_handler(bucket_name: str, item_name: str, file_store: FileStore):
    """Handle retrieving an object."""
    item = file_store.get_item(bucket_name, item_name)
    if not item:
        return Response(status_code=404)
    
    # Set up response headers
    headers = {}
    
    # Format last modified date
    if hasattr(item, 'creation_date'):
        last_modified = item.creation_date
    else:
        last_modified = item.modified_date
    last_modified_dt = datetime.strptime(last_modified, '%Y-%m-%dT%H:%M:%S.000Z')
    last_modified = last_modified_dt.strftime('%a, %d %b %Y %H:%M:%S GMT')
    
    headers["Last-Modified"] = last_modified
    headers["Etag"] = f'"{item.md5}"'
    headers["Accept-Ranges"] = "bytes"
    headers["Content-Type"] = item.content_type
    headers["Content-Length"] = str(item.size)
    
    # Return the file content
    return StreamingResponse(
        iter([item.io.read()]),
        status_code=200,
        headers=headers,
        media_type=item.content_type
    )


def run_server(hostname="localhost", port=10001, root=None, pull_from_aws=False):
    """Run the FastAPI server."""
    global config
    
    # Update configuration
    config["hostname"] = hostname
    config["port"] = port
    if root:
        config["root"] = root
    config["pull_from_aws"] = pull_from_aws
    
    # Initialize file store
    global file_store
    file_store = FileStore(config["root"])
    
    # Run server
    logger.info(f"Starting server on {hostname}:{port}, root directory: {config['root']}")
    uvicorn.run(app, host=hostname, port=port)


if __name__ == "__main__":
    run_server() 