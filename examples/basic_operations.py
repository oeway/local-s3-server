"""
Basic S3 operations example using local-s3-server.

This example demonstrates how to:
1. Create a bucket
2. Upload a file
3. List buckets
4. List objects in a bucket
5. Download a file
6. Delete a file
7. Delete a bucket
"""

import boto3
import os
from io import BytesIO

# Configure the S3 client to use the local server
s3 = boto3.client(
    's3',
    endpoint_url='http://localhost:10001',
    aws_access_key_id='test',
    aws_secret_access_key='test',
    region_name='us-east-1'
)

# Create a bucket
bucket_name = 'example-bucket'
try:
    s3.create_bucket(Bucket=bucket_name)
    print(f"Created bucket: {bucket_name}")
except Exception as e:
    print(f"Error creating bucket: {e}")

# Upload a file
file_content = b"Hello, this is a test file!"
file_key = 'test-file.txt'
try:
    s3.put_object(
        Bucket=bucket_name,
        Key=file_key,
        Body=file_content
    )
    print(f"Uploaded file: {file_key}")
except Exception as e:
    print(f"Error uploading file: {e}")

# List all buckets
try:
    response = s3.list_buckets()
    print("Buckets:")
    for bucket in response['Buckets']:
        print(f"  - {bucket['Name']}")
except Exception as e:
    print(f"Error listing buckets: {e}")

# List objects in the bucket
try:
    response = s3.list_objects_v2(Bucket=bucket_name)
    print(f"Objects in {bucket_name}:")
    for obj in response.get('Contents', []):
        print(f"  - {obj['Key']} ({obj['Size']} bytes)")
except Exception as e:
    print(f"Error listing objects: {e}")

# Download the file
try:
    response = s3.get_object(Bucket=bucket_name, Key=file_key)
    downloaded_content = response['Body'].read()
    print(f"Downloaded file content: {downloaded_content.decode('utf-8')}")
except Exception as e:
    print(f"Error downloading file: {e}")

# Upload a file to a nested path
nested_key = 'folder1/folder2/nested-file.txt'
try:
    s3.put_object(
        Bucket=bucket_name,
        Key=nested_key,
        Body=b"This is a nested file!"
    )
    print(f"Uploaded nested file: {nested_key}")
except Exception as e:
    print(f"Error uploading nested file: {e}")

# List objects with a prefix
try:
    response = s3.list_objects_v2(Bucket=bucket_name, Prefix='folder1/')
    print(f"Objects with prefix 'folder1/':")
    for obj in response.get('Contents', []):
        print(f"  - {obj['Key']}")
except Exception as e:
    print(f"Error listing objects with prefix: {e}")

# Generate a presigned URL for the file
try:
    presigned_url = s3.generate_presigned_url(
        'get_object',
        Params={'Bucket': bucket_name, 'Key': file_key},
        ExpiresIn=3600
    )
    print(f"Presigned URL: {presigned_url}")
    print("You can use this URL to access the file without authentication for 1 hour.")
except Exception as e:
    print(f"Error generating presigned URL: {e}")

# Delete the files
try:
    s3.delete_object(Bucket=bucket_name, Key=file_key)
    print(f"Deleted file: {file_key}")
    
    s3.delete_object(Bucket=bucket_name, Key=nested_key)
    print(f"Deleted file: {nested_key}")
except Exception as e:
    print(f"Error deleting files: {e}")

# Delete the bucket
try:
    s3.delete_bucket(Bucket=bucket_name)
    print(f"Deleted bucket: {bucket_name}")
except Exception as e:
    print(f"Error deleting bucket: {e}")

print("\nExample completed successfully!") 