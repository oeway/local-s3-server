"""
Image handling example using local-s3-server.

This example demonstrates how to:
1. Upload an image to S3
2. Set the correct content type
3. Download the image
4. Generate a presigned URL for the image
"""

import boto3
import os
from io import BytesIO
from PIL import Image
import requests
import tempfile

# Configure the S3 client to use the local server
s3 = boto3.client(
    's3',
    endpoint_url='http://localhost:10001',
    aws_access_key_id='test',
    aws_secret_access_key='test',
    region_name='us-east-1'
)

# Create a bucket
bucket_name = 'image-bucket'
try:
    s3.create_bucket(Bucket=bucket_name)
    print(f"Created bucket: {bucket_name}")
except Exception as e:
    print(f"Error creating bucket: {e}")

# Create a simple image using PIL
def create_test_image():
    """Create a simple test image."""
    img = Image.new('RGB', (100, 100), color='red')
    img_bytes = BytesIO()
    img.save(img_bytes, format='PNG')
    img_bytes.seek(0)
    return img_bytes

# Upload the image
image_key = 'test-image.png'
try:
    img_data = create_test_image()
    s3.put_object(
        Bucket=bucket_name,
        Key=image_key,
        Body=img_data,
        ContentType='image/png'  # Set the correct content type
    )
    print(f"Uploaded image: {image_key}")
except Exception as e:
    print(f"Error uploading image: {e}")

# Download the image
try:
    response = s3.get_object(Bucket=bucket_name, Key=image_key)
    
    # Check the content type
    content_type = response['ContentType']
    print(f"Downloaded image content type: {content_type}")
    
    # Save the image to a temporary file
    with tempfile.NamedTemporaryFile(suffix='.png', delete=False) as tmp_file:
        tmp_file.write(response['Body'].read())
        tmp_path = tmp_file.name
    
    print(f"Image saved to temporary file: {tmp_path}")
except Exception as e:
    print(f"Error downloading image: {e}")

# Generate a presigned URL for the image
try:
    presigned_url = s3.generate_presigned_url(
        'get_object',
        Params={'Bucket': bucket_name, 'Key': image_key},
        ExpiresIn=3600
    )
    print(f"Presigned URL for image: {presigned_url}")
    
    # Use the presigned URL to download the image
    response = requests.get(presigned_url)
    if response.status_code == 200:
        print(f"Successfully accessed image via presigned URL")
        print(f"Content type from presigned URL: {response.headers.get('Content-Type')}")
    else:
        print(f"Failed to access image via presigned URL: {response.status_code}")
except Exception as e:
    print(f"Error with presigned URL: {e}")

# Clean up
try:
    s3.delete_object(Bucket=bucket_name, Key=image_key)
    print(f"Deleted image: {image_key}")
    
    s3.delete_bucket(Bucket=bucket_name)
    print(f"Deleted bucket: {bucket_name}")
    
    # Remove the temporary file
    if 'tmp_path' in locals():
        os.unlink(tmp_path)
        print(f"Removed temporary file: {tmp_path}")
except Exception as e:
    print(f"Error during cleanup: {e}")

print("\nImage handling example completed successfully!") 