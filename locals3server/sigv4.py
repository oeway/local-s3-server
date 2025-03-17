"""
AWS Signature Version 4 signing utilities.
"""

import datetime
import hashlib
import hmac
import urllib.parse
from typing import Dict, List, Optional, Union

def sign(key: bytes, msg: str) -> bytes:
    """Create a signature using the HMAC-SHA256 algorithm."""
    return hmac.new(key, msg.encode('utf-8'), hashlib.sha256).digest()

def get_signature_key(key: str, date_stamp: str, region: str, service: str) -> bytes:
    """Get a signing key for AWS Signature Version 4."""
    k_date = sign(f'AWS4{key}'.encode('utf-8'), date_stamp)
    k_region = sign(k_date, region)
    k_service = sign(k_region, service)
    k_signing = sign(k_service, 'aws4_request')
    return k_signing

def create_canonical_request(
    method: str,
    canonical_uri: str,
    query_params: Dict[str, str],
    headers: Dict[str, str],
    signed_headers: List[str],
    payload_hash: str
) -> str:
    """Create a canonical request string for AWS Signature Version 4."""
    canonical_query_string = '&'.join([
        f"{urllib.parse.quote(k)}={urllib.parse.quote(v)}"
        for k, v in sorted(query_params.items())
    ])
    
    canonical_headers = ''.join([
        f"{header.lower()}:{headers[header]}\n"
        for header in sorted(signed_headers)
    ])
    
    signed_headers_str = ';'.join(sorted(h.lower() for h in signed_headers))
    
    return '\n'.join([
        method,
        canonical_uri,
        canonical_query_string,
        canonical_headers,
        signed_headers_str,
        payload_hash
    ])

def create_string_to_sign(
    algorithm: str,
    request_datetime: datetime.datetime,
    credential_scope: str,
    canonical_request: str
) -> str:
    """Create a string to sign for AWS Signature Version 4."""
    return '\n'.join([
        algorithm,
        request_datetime.strftime('%Y%m%dT%H%M%SZ'),
        credential_scope,
        hashlib.sha256(canonical_request.encode('utf-8')).hexdigest()
    ])

def generate_presigned_url(
    method: str,
    host: str,
    region: str,
    bucket: str,
    key: str,
    access_key: str,
    secret_key: str,
    expires_in: int = 3600,
    additional_params: Optional[Dict[str, str]] = None
) -> str:
    """
    Generate a presigned URL using AWS Signature Version 4.
    
    Args:
        method: HTTP method ('GET', 'PUT', etc.)
        host: Host name (e.g., 's3.amazonaws.com')
        region: AWS region (e.g., 'us-east-1')
        bucket: S3 bucket name
        key: S3 object key
        access_key: AWS access key ID
        secret_key: AWS secret access key
        expires_in: URL expiration time in seconds (default: 1 hour)
        additional_params: Additional query parameters to include in the URL
    
    Returns:
        str: The presigned URL
    """
    # Initialize request parameters
    service = 's3'
    request_datetime = datetime.datetime.utcnow()
    datestamp = request_datetime.strftime('%Y%m%d')
    amz_date = request_datetime.strftime('%Y%m%dT%H%M%SZ')
    
    # Create canonical URI
    canonical_uri = f'/{bucket}/{key}' if bucket else '/'
    
    # Initialize query parameters
    query_params = additional_params.copy() if additional_params else {}
    query_params.update({
        'X-Amz-Algorithm': 'AWS4-HMAC-SHA256',
        'X-Amz-Credential': f'{access_key}/{datestamp}/{region}/{service}/aws4_request',
        'X-Amz-Date': amz_date,
        'X-Amz-Expires': str(expires_in),
        'X-Amz-SignedHeaders': 'host'
    })
    
    # Create canonical request
    headers = {'host': host}
    signed_headers = ['host']
    payload_hash = 'UNSIGNED-PAYLOAD'
    
    canonical_request = create_canonical_request(
        method,
        canonical_uri,
        query_params,
        headers,
        signed_headers,
        payload_hash
    )
    
    # Create string to sign
    credential_scope = f'{datestamp}/{region}/{service}/aws4_request'
    string_to_sign = create_string_to_sign(
        'AWS4-HMAC-SHA256',
        request_datetime,
        credential_scope,
        canonical_request
    )
    
    # Calculate signature
    signing_key = get_signature_key(secret_key, datestamp, region, service)
    signature = hmac.new(signing_key, string_to_sign.encode('utf-8'), hashlib.sha256).hexdigest()
    
    # Add signature to query parameters
    query_params['X-Amz-Signature'] = signature
    
    # Construct the final URL
    query_string = '&'.join([
        f"{urllib.parse.quote(k)}={urllib.parse.quote(v)}"
        for k, v in sorted(query_params.items())
    ])
    
    return f"https://{host}{canonical_uri}?{query_string}"

def verify_presigned_url(
    method: str,
    uri: str,
    query_params: Dict[str, str],
    headers: Dict[str, str],
    region: str,
    secret_key: str
) -> bool:
    """
    Verify a presigned URL using AWS Signature Version 4.
    
    Args:
        method: HTTP method ('GET', 'PUT', etc.)
        uri: Request URI
        query_params: Query parameters from the request
        headers: Request headers
        region: AWS region
        secret_key: AWS secret access key
    
    Returns:
        bool: True if the signature is valid, False otherwise
    """
    try:
        # Extract required parameters
        algorithm = query_params.get('X-Amz-Algorithm')
        if algorithm != 'AWS4-HMAC-SHA256':
            return False
        
        credential = query_params.get('X-Amz-Credential', '').split('/')
        if len(credential) != 5:
            return False
        
        access_key = credential[0]
        datestamp = credential[1]
        credential_region = credential[2]
        service = credential[3]
        
        if credential_region != region or service != 's3':
            return False
        
        amz_date = query_params.get('X-Amz-Date')
        if not amz_date:
            return False
        
        request_datetime = datetime.datetime.strptime(amz_date, '%Y%m%dT%H%M%SZ')
        expires = int(query_params.get('X-Amz-Expires', '0'))
        
        # Check if URL has expired
        now = datetime.datetime.utcnow()
        if now - request_datetime > datetime.timedelta(seconds=expires):
            return False
        
        # Get provided signature
        provided_signature = query_params.get('X-Amz-Signature')
        if not provided_signature:
            return False
        
        # Remove signature from query parameters for canonical request
        query_params_without_sig = {
            k: v for k, v in query_params.items()
            if k != 'X-Amz-Signature'
        }
        
        # Create canonical request
        canonical_uri = urllib.parse.quote(uri, safe='/~')
        
        # Sort and encode query parameters
        canonical_querystring = '&'.join(
            f"{urllib.parse.quote(k, safe='~')}={urllib.parse.quote(v, safe='~')}"
            for k, v in sorted(query_params_without_sig.items())
        )
        
        # Create canonical headers
        signed_headers = query_params.get('X-Amz-SignedHeaders', '').split(';')
        canonical_headers = ''.join(
            f"{header}:{headers.get(header, '').strip()}\n"
            for header in sorted(signed_headers)
        )
        
        # Create signed headers string
        signed_headers_str = ';'.join(sorted(signed_headers))
        
        # Create canonical request
        canonical_request = '\n'.join([
            method,
            canonical_uri,
            canonical_querystring,
            canonical_headers,
            signed_headers_str,
            'UNSIGNED-PAYLOAD'
        ])
        
        # Create string to sign
        credential_scope = f'{datestamp}/{region}/{service}/aws4_request'
        string_to_sign = '\n'.join([
            'AWS4-HMAC-SHA256',
            amz_date,
            credential_scope,
            hashlib.sha256(canonical_request.encode('utf-8')).hexdigest()
        ])
        
        # Calculate signature
        signing_key = get_signature_key(secret_key, datestamp, region, service)
        calculated_signature = hmac.new(signing_key, string_to_sign.encode('utf-8'), hashlib.sha256).hexdigest()
        
        # Compare signatures
        return hmac.compare_digest(calculated_signature, provided_signature)
        
    except Exception as e:
        import traceback
        import logging
        logging.error(f"Error verifying presigned URL: {e}")
        logging.error(traceback.format_exc())
        return False 