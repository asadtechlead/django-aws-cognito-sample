import hmac
import hashlib
import base64
import boto3
from django.conf import settings

def generate_secret_hash(username):
    secret_hash = hmac.new(
        key=settings.COGNITO_CLIENT_SECRET.encode('utf-8'),
        msg=username.encode('utf-8') + settings.COGNITO_CLIENT_ID.encode('utf-8'),
        digestmod=hashlib.sha256
    ).digest()

    return base64.b64encode(secret_hash).decode('utf-8')

def get_cognito_client():
    return boto3.client('cognito-idp', region_name=settings.AWS_REGION)
