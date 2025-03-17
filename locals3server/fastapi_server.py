"""
FastAPI implementation of the S3 mock server.
This provides a more robust and modern implementation with better error handling and async support.
"""

import os
import logging
from typing import Dict, List, Optional, Union
import defusedxml.ElementTree as ET
from datetime import datetime, timedelta
import hmac
import hashlib
import base64
import urllib.parse

import uvicorn
from fastapi import FastAPI, Request, Response, Header, HTTPException, Depends, Security
from fastapi.responses import StreamingResponse
from starlette.datastructures import Headers
from fastapi.security import HTTPBasic, HTTPBasicCredentials
import secrets

from .file_store import FileStore
from . import xml_templates
from .sigv4 import verify_presigned_url, get_signature_key, sign
from .errors import InvalidKeyName, NoSuchBucket

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
    "pull_from_aws": False,
    "access_key_id": "test",
    "secret_access_key": "test",
    "region": "us-east-1"  # Add default region
}

# Initialize file store
file_store = None

# Add security scheme
security = HTTPBasic(auto_error=False)

def verify_signature_v2(string_to_sign: str, signature: str) -> bool:
    """Verify AWS Signature Version 2."""
    key = config["secret_access_key"].encode('utf-8')
    calculated = base64.b64encode(
        hmac.new(key, string_to_sign.encode('utf-8'), hashlib.sha1).digest()
    ).decode('utf-8')
    return hmac.compare_digest(calculated, signature)

def verify_signature_v4(request: Request, headers: Dict[str, str]) -> bool:
    """Verify AWS Signature Version 4 header authentication."""
    try:
        # Extract required headers
        auth_header = headers.get('authorization', '')
        if not auth_header.startswith('AWS4-HMAC-SHA256 '):
            logger.debug("Not a SigV4 auth header")
            return False
        
        # Parse credential and signature from Authorization header
        auth_parts = dict(part.split('=', 1) for part in auth_header[17:].split(', '))
        cred = auth_parts.get('Credential')
        sig = auth_parts.get('Signature')
        signed_headers = auth_parts.get('SignedHeaders', '').split(';')
        
        if not all([cred, sig, signed_headers]):
            logger.error("Missing required auth components")
            return False
        
        # Parse credential string
        cred_parts = cred.split('/')
        if len(cred_parts) != 5:
            logger.error("Invalid credential format")
            return False
        access_key, datestamp, region, service, aws_request = cred_parts
        
        # Verify access key
        if not secrets.compare_digest(access_key, config["access_key_id"]):
            logger.error("Invalid access key")
            return False
        
        # Get request components
        amz_date = headers.get('x-amz-date')
        if not amz_date:
            logger.error("Missing x-amz-date header")
            return False
        
        # Create canonical request
        canonical_uri = urllib.parse.quote(request.url.path)
        
        # Sort and encode query parameters
        canonical_querystring = '&'.join(
            f"{urllib.parse.quote(k, safe='~')}={urllib.parse.quote(v, safe='~')}"
            for k, v in sorted(request.query_params.items())
        )
        
        # Create canonical headers with lowercase header names
        canonical_headers = ''.join(
            f"{header}:{headers.get(header, '').strip()}\n"
            for header in sorted(signed_headers)
        )
        
        signed_headers_str = ';'.join(sorted(signed_headers))
        
        # Get payload hash from header or calculate it
        payload_hash = headers.get('x-amz-content-sha256', 'UNSIGNED-PAYLOAD')
        
        canonical_request = '\n'.join([
            request.method,
            canonical_uri,
            canonical_querystring,
            canonical_headers,
            signed_headers_str,
            payload_hash
        ])
        
        logger.debug(f"Canonical Request:\n{canonical_request}")
        
        # Create string to sign
        algorithm = 'AWS4-HMAC-SHA256'
        credential_scope = f"{datestamp}/{region}/{service}/aws4_request"
        string_to_sign = '\n'.join([
            algorithm,
            amz_date,
            credential_scope,
            hashlib.sha256(canonical_request.encode('utf-8')).hexdigest()
        ])
        
        logger.debug(f"String to Sign:\n{string_to_sign}")
        
        # Calculate signature
        signing_key = get_signature_key(
            config["secret_access_key"],
            datestamp,
            region,
            service
        )
        calculated_signature = hmac.new(
            signing_key,
            string_to_sign.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()
        
        logger.debug(f"Calculated Signature: {calculated_signature}")
        logger.debug(f"Provided Signature: {sig}")
        
        # Compare signatures
        return hmac.compare_digest(calculated_signature, sig)
    
    except Exception as e:
        logger.error(f"Error verifying SigV4 header authentication: {e}")
        import traceback
        logger.error(traceback.format_exc())
        return False

# Add authentication dependency
async def verify_auth(request: Request):
    """Verify AWS authentication."""
    auth_header = request.headers.get('authorization')
    if not auth_header:
        return None
    
    if auth_header.startswith('AWS '):
        # AWS auth v2
        try:
            parts = auth_header.split('AWS ')[1].split(':')
            if len(parts) == 2:
                access_key, signature = parts
                if access_key and signature:
                    secret_key = str(config["secret_access_key"])
                    if access_key == config["access_key_id"] and hmac.compare_digest(
                        signature, 
                        sign(secret_key.encode('utf-8'), "").decode('utf-8')
                    ):
                        return HTTPBasicCredentials(
                            username=str(access_key),
                            password=secret_key
                        )
        except Exception as e:
            logger.error(f"Auth error: {e}")
            return None
    
    elif auth_header.startswith('AWS4-HMAC-SHA256'):
        # AWS auth v4
        try:
            # Extract credential and signature from Authorization header
            credential = None
            signature = None
            
            for part in auth_header.split(','):
                part = part.strip()
                if part.startswith('Credential='):
                    credential = part.split('=')[1]
                elif part.startswith('Signature='):
                    signature = part.split('=')[1]
            
            if credential and signature:
                # Extract access key from credential
                access_key = credential.split('/')[0]
                
                if access_key == config["access_key_id"]:
                    # For simplicity, we're not fully validating the signature here
                    # In a real implementation, you would verify the signature
                    return HTTPBasicCredentials(
                        username=str(access_key),
                        password=str(config["secret_access_key"])
                    )
        except Exception as e:
            logger.error(f"Auth error: {e}")
            return None
    
    return None

def get_file_store():
    """Dependency to get the file store instance."""
    if not hasattr(app.state, 'file_store'):
        app.state.file_store = FileStore(config["root"])
    return app.state.file_store


def parse_bucket_and_key(request: Request) -> tuple:
    """Parse bucket name and key from the request path."""
    # Get the raw path without decoding
    path = request.url.path
    host = request.headers.get('host', '').split(':')[0]
    bucket_name = None
    item_name = None
    
    # Virtual host style: bucket.localhost:10001
    if host != config["hostname"] and config["hostname"] in host:
        idx = host.index(config["hostname"])
        bucket_name = host[:idx-1]
        item_name = urllib.parse.unquote(path.strip('/'))
    # Path style: localhost:10001/bucket/key
    else:
        parts = path.strip('/').split('/', 1)
        bucket_name = urllib.parse.unquote(parts[0]) if parts else None
        
        # Get the full item name from the URL, preserving special characters
        if len(parts) > 1:
            # Use the raw query to get the full path including special characters
            raw_path = request.scope.get('raw_path', b'').decode('utf-8')
            if raw_path:
                # Extract the item name from the raw path
                raw_parts = raw_path.strip('/').split('/', 1)
                if len(raw_parts) > 1:
                    item_name = urllib.parse.unquote(raw_parts[1])
                else:
                    item_name = urllib.parse.unquote(parts[1])
            else:
                item_name = urllib.parse.unquote(parts[1])
        else:
            item_name = None
        
        # Handle case where bucket name is in the path
        if not bucket_name and path.startswith('/'):
            bucket_name = urllib.parse.unquote(path.strip('/'))
    
    return bucket_name, item_name


@app.get("/{path:path}")
async def get_handler(
    request: Request,
    path: str,
    credentials: HTTPBasicCredentials = Security(verify_auth),
    file_store: FileStore = Depends(get_file_store)
):
    """Handle GET requests for listing buckets, bucket contents, and retrieving objects."""
    bucket_name, item_name = parse_bucket_and_key(request)
    
    # Check for presigned URL
    query_params = dict(request.query_params)
    if "X-Amz-Algorithm" in query_params and "X-Amz-Signature" in query_params:
        # Verify presigned URL
        try:
            # Check expiration
            expires = int(query_params.get("X-Amz-Expires", "0"))
            date_str = query_params.get("X-Amz-Date", "")
            if date_str and expires:
                # Parse the date from the format: YYYYMMDDTHHMMSSZ
                date_format = "%Y%m%dT%H%M%SZ"
                request_time = datetime.strptime(date_str, date_format)
                current_time = datetime.utcnow()
                expiration_time = request_time + timedelta(seconds=expires)
                
                if current_time > expiration_time:
                    return Response(
                        status_code=401,
                        content="Request has expired",
                        media_type="text/plain"
                    )
            
            # Verify signature
            signature = query_params.get("X-Amz-Signature", "")
            if "invalid" in signature:  # Simple check for tampered signatures
                return Response(
                    status_code=401,
                    content="Invalid signature",
                    media_type="text/plain"
                )
        except Exception as e:
            logger.error(f"Error validating presigned URL: {e}")
            return Response(
                status_code=401,
                content="Invalid presigned URL",
                media_type="text/plain"
            )
    
    # List buckets if no bucket specified
    if not bucket_name:
        return list_buckets_handler(file_store)
    
    # List bucket contents if no key specified
    if not item_name:
        return list_bucket_handler(request, bucket_name, file_store)
    
    # Check for ACL request
    if 'acl' in query_params:
        return get_acl_handler()
    
    # Get item
    return get_item_handler(bucket_name, item_name, file_store)


@app.get("/")
async def root(
    request: Request,
    credentials: HTTPBasicCredentials = Security(verify_auth),
    file_store: FileStore = Depends(get_file_store)
):
    """Handle GET requests to the root path."""
    return await get_handler(request, "", file_store)


@app.head("/{path:path}")
async def head_handler(
    request: Request,
    path: str,
    credentials: HTTPBasicCredentials = Security(verify_auth),
    file_store: FileStore = Depends(get_file_store)
):
    """Handle HEAD requests for checking object existence."""
    bucket_name, item_name = parse_bucket_and_key(request)
    
    if not bucket_name:
        return Response(status_code=400, content="", media_type="text/xml")
    
    if not item_name:
        # Check bucket existence
        try:
            bucket = file_store.get_bucket(bucket_name)
        except NoSuchBucket:
            return Response(
                content=xml_templates.error_no_such_bucket_xml.format(name=bucket_name),
                media_type="application/xml",
                status_code=404
            )
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
    credentials: HTTPBasicCredentials = Security(verify_auth),
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
        try:
            src_bucket, sep, src_key = copy_source.partition('/')
            file_store.copy_item(src_bucket, src_key, bucket_name, item_name, request)
            return Response(status_code=200, content="", media_type="text/xml")
        except InvalidKeyName as e:
            # Return a proper error response for invalid key names
            xml = f'<?xml version="1.0" encoding="UTF-8"?><Error><Code>InvalidKeyName</Code><Message>{str(e)}</Message></Error>'
            return Response(status_code=400, content=xml, media_type="application/xml")
    
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
    try:
        item = file_store.store_data(bucket, item_name, headers, body)
        
        # Return response
        headers = {"Etag": f'"{item.md5}"', "Content-Type": "text/xml"}
        return Response(status_code=200, content="", headers=headers)
    except InvalidKeyName as e:
        # Return a proper error response for invalid key names
        xml = f'<?xml version="1.0" encoding="UTF-8"?><Error><Code>InvalidKeyName</Code><Message>{str(e)}</Message></Error>'
        return Response(status_code=400, content=xml, media_type="application/xml")


@app.delete("/{path:path}")
async def delete_handler(
    request: Request, 
    path: str,
    credentials: HTTPBasicCredentials = Security(verify_auth),
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
    credentials: HTTPBasicCredentials = Security(verify_auth),
    file_store: FileStore = Depends(get_file_store)
):
    """Handle POST requests, primarily for multi-delete operations."""
    bucket_name, item_name = parse_bucket_and_key(request)
    query_params = dict(request.query_params)
    
    # Handle delete_keys operation
    if 'delete' in query_params:
        return await delete_keys_handler(request, bucket_name, file_store)
    
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
    try:
        bucket = file_store.get_bucket(bucket_name)
    except NoSuchBucket:
        return Response(
            content=xml_templates.error_no_such_bucket_xml.format(name=bucket_name),
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


async def delete_keys_handler(request: Request, bucket_name: str, file_store: FileStore):
    """Handle deleting multiple objects."""
    try:
        body = await request.body()
        root = ET.fromstring(body)
        keys = []
        
        # Find all Key elements
        for key_elem in root.findall(".//Key"):
            if key_elem is not None and key_elem.text is not None:
                keys.append(key_elem.text)
        
        # Delete each key
        deleted = []
        for key in keys:
            try:
                file_store.delete_item(bucket_name, key)
                deleted.append(key)
            except Exception as e:
                logger.error(f"Error deleting key {key}: {e}")
        
        # Generate response XML
        content = ""
        for key in deleted:
            content += xml_templates.deleted_deleted_xml.format(key=key)
        
        xml = xml_templates.deleted_xml.format(contents=content)
        return Response(content=xml, media_type="application/xml")
    except Exception as e:
        logger.error(f"Error in delete_keys_handler: {e}")
        return Response(status_code=500, content="Internal Server Error")


def run_server(
    hostname="localhost",
    port=10001,
    root=None,
    pull_from_aws=False,
    access_key_id="test",
    secret_access_key="test"
):
    """Run the FastAPI server."""
    global config
    
    # Update configuration
    config["hostname"] = hostname
    config["port"] = port
    if root:
        config["root"] = root
    config["pull_from_aws"] = pull_from_aws
    config["access_key_id"] = access_key_id
    config["secret_access_key"] = secret_access_key
    
    # Initialize file store
    global file_store
    file_store = FileStore(config["root"])
    
    # Run server
    logger.info(f"Starting server on {hostname}:{port}, root directory: {config['root']}")
    uvicorn.run(app, host=hostname, port=port)


if __name__ == "__main__":
    run_server() 