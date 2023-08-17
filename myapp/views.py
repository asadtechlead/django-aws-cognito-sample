from django.shortcuts import render
import botocore.exceptions  # Import the botocore.exceptions.ClientError class
import hmac
import hashlib
import base64
# Create your views here.

# views.py
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
import json
import jwt
from django.conf import settings
from .cognito_utils import generate_secret_hash, get_cognito_client

class SignUpView(APIView):
    def post(self, request):
        email = request.data.get('email')
        password = request.data.get('password')
        phone_number = request.data.get('phone_number')
        cognito_client = get_cognito_client()
        secret_hash = generate_secret_hash(email)

        try:
            response = cognito_client.sign_up(
                ClientId=settings.COGNITO_CLIENT_ID,
                SecretHash=secret_hash,
                Username=email,
                Password=password,
                UserAttributes=[
                    {'Name': 'email', 'Value': email},
                    {'Name': 'name', 'Value': 'Asad'},
                    {'Name': 'phone_number', 'Value': phone_number}
                ]
            )
            return Response({"message": "User signed up successfully"}, status=status.HTTP_201_CREATED)
        except botocore.exceptions.ClientError as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)

class ConfirmSignUpView(APIView):
    def post(self, request):
        email = request.data.get('email')
        confirmation_code = request.data.get('confirmation_code')
        cognito_client = get_cognito_client()
        secret_hash = generate_secret_hash(email)
        try:
            response = cognito_client.confirm_sign_up(
                ClientId=settings.COGNITO_CLIENT_ID,
                SecretHash=secret_hash,
                Username=email,
                ConfirmationCode=confirmation_code
            )
            return Response({"message": "User confirmed successfully"}, status=status.HTTP_200_OK)
        except botocore.exceptions.ClientError as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)

# Token validation helper function
def validate_cognito_token(token):
    try:
        claims = jwt.decode(token, verify=False)
        return claims
    except jwt.ExpiredSignatureError:
        return None

# Use 'validate_cognito_token' in your views to validate and process tokens.



from django.contrib.auth import authenticate, login
from django.contrib.auth.models import User
from django.core.exceptions import ObjectDoesNotExist

class SignInView(APIView):
    def post(self, request):
            email = request.POST.get('email')
            password = request.POST.get('password')
            secret_hash = generate_secret_hash(email)
            cognito_client = get_cognito_client()

            try:
                response = cognito_client.initiate_auth(
                    AuthFlow='USER_PASSWORD_AUTH',
                    ClientId=settings.COGNITO_CLIENT_ID,
                    AuthParameters={
                        'USERNAME': email,
                        'PASSWORD': password,
                        'SECRET_HASH': secret_hash
                    }
                )
                print(response)  # Print the entire response for inspection
                # Extract the access token from the response
                access_token = response['AuthenticationResult']['AccessToken']

                return Response({"access_token": access_token, "message":"Got AccessToken for further API calls, user is signed In"}, status=status.HTTP_200_OK)
            except botocore.exceptions.ClientError as e:
                return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)

class RequestPasswordResetView(APIView):
    def post(self, request):
        email = request.data.get('email')
        cognito_client = get_cognito_client()
        secret_hash = generate_secret_hash(email)
        try:
            user = User.objects.get(email=email)
            response = cognito_client.forgot_password(
                ClientId=settings.COGNITO_CLIENT_ID,
                SecretHash=secret_hash,
                Username=email
            )
            return Response({"message": "Password reset requested successfully"}, status=status.HTTP_200_OK)
        except ObjectDoesNotExist:
            return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)
        except botocore.exceptions.ClientError as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)

class ConfirmPasswordResetView(APIView):
    def post(self, request):
        email = request.data.get('email')
        confirmation_code = request.data.get('confirmation_code')
        new_password = request.data.get('new_password')
        cognito_client = get_cognito_client()
        secret_hash = generate_secret_hash(email)
        try:
            response = cognito_client.confirm_forgot_password(
                ClientId=settings.COGNITO_CLIENT_ID,
                SecretHash=secret_hash,
                Username=email,
                ConfirmationCode=confirmation_code,
                Password=new_password
            )
            return Response({"message": "Password reset confirmed successfully"}, status=status.HTTP_200_OK)
        except botocore.exceptions.ClientError as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)

class VerifyPhoneNumberView(APIView):
    def post(self, request):
        email = request.data.get('email')
        phone_number = request.data.get('phone_number')
        cognito_client = get_cognito_client()
        try:
            response = cognito_client.update_user_attributes(
                UserAttributes=[
                    {'Name': 'phone_number', 'Value': phone_number},
                ],
                AccessToken=request.data.get('access_token'),
            )
            return Response({"message": "Phone number updated successfully"}, status=status.HTTP_200_OK)
        except botocore.exceptions.ClientError as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)

class ConfirmSMSCodeView(APIView):
    def post(self, request):
        email = request.data.get('email')
        sms_code = request.data.get('sms_code')
        cognito_client = get_cognito_client()
        secret_hash = generate_secret_hash(email)
        try:
            response = cognito_client.confirm_sign_up(
                ClientId=settings.COGNITO_CLIENT_ID,
                Username=email,
                SecretHash=secret_hash,
                ConfirmationCode=sms_code
            )
            return Response({"message": "SMS code confirmed successfully"}, status=status.HTTP_200_OK)
        except botocore.exceptions.ClientError as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)



