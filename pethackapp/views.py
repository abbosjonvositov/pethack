# views.py
from django.shortcuts import get_object_or_404
from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login, logout
from django.core.mail import send_mail
from drf_yasg.utils import swagger_auto_schema
from rest_framework.authentication import SessionAuthentication, TokenAuthentication
from rest_framework.permissions import IsAuthenticated
from django.conf import settings
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.authtoken.models import Token
from .models import EmailVerification
import random
from .serializers import *
from django.db.utils import IntegrityError
from django.contrib.auth.password_validation import validate_password
from django.core.validators import validate_email
from django.core.exceptions import ValidationError
from django.core.exceptions import ObjectDoesNotExist

from .serializers import UserSerializer


class SignupAPIView(APIView):
    @swagger_auto_schema(
        request_body=SignupSerializer,
        responses={status.HTTP_201_CREATED: 'Signup successful. Please verify your email.'}
    )
    def post(self, request):

        try:
            email = request.data.get('email')
            username = request.data.get('username')
            password = request.data.get('password')

            if not email or not username or not password:
                return Response({'detail': 'Email, username, and password are required.'},
                                status=status.HTTP_400_BAD_REQUEST)

            validate_email(email)
            validate_password(password)

            user = User.objects.create_user(username=username, email=email, password=password)

            code = ''.join([str(random.randint(0, 9)) for _ in range(4)])

            send_mail(
                'Verification Code',
                f'Your verification code is: {code}',
                settings.EMAIL_HOST_USER,
                [email],
                fail_silently=False,
            )

            EmailVerification.objects.create(user=user, code=code)

            token = Token.objects.create(user=user)

            return Response({'detail': 'Signup successful. Please verify your email.', 'token': token.key},
                            status=status.HTTP_201_CREATED)

        except ValidationError as e:
            return Response({'detail': str(e)}, status=status.HTTP_400_BAD_REQUEST)

        except IntegrityError:
            return Response({'detail': 'Username already exists.'}, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            return Response({'detail': 'An error occurred while processing your request.'},
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class VerifyEmailAPIView(APIView):
    authentication_classes = [SessionAuthentication, TokenAuthentication]
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_description="Verify user's email address using verification code.",
        request_body=EmailVerificationSerializer,  # Define serializer for the request body
        responses={
            status.HTTP_200_OK: "Email verified successfully.",
            status.HTTP_400_BAD_REQUEST: "Email and code are required. Email is already in use. Invalid verification code."
        }
    )
    def post(self, request):
        email = request.data.get('email')
        code = request.data.get('code')

        if not email or not code:
            return Response({'detail': 'Email and code are required.'}, status=status.HTTP_400_BAD_REQUEST)

        users = User.objects.filter(email=email)
        if users.count() != 1:
            return Response({'detail': 'Email is already in use.'}, status=status.HTTP_400_BAD_REQUEST)

        user = users.first()
        email_verification = get_object_or_404(EmailVerification, user=user)

        if email_verification.code == code:
            email_verification.verified = True
            email_verification.save()
            return Response({'detail': 'Email verified successfully.'}, status=status.HTTP_200_OK)
        else:
            return Response({'detail': 'Invalid verification code.'}, status=status.HTTP_400_BAD_REQUEST)


class LoginAPIView(APIView):
    @swagger_auto_schema(
        operation_description="Login with username and password. Returns token and username if successful.",
        request_body=LoginSerializer,
        responses={
            status.HTTP_200_OK: "Login successful. Token and username returned.",
            status.HTTP_400_BAD_REQUEST: "Invalid username or password. Email not verified. Email verification record not found.",
            status.HTTP_401_UNAUTHORIZED: "Username and password are required.",
            status.HTTP_500_INTERNAL_SERVER_ERROR: "An error occurred while processing your request. Please try again later."
        }
    )
    def post(self, request):
        try:
            username = request.data.get('username')
            password = request.data.get('password')

            if not username or not password:
                return Response({'detail': 'Username and password are required.'}, status=status.HTTP_400_BAD_REQUEST)

            user = authenticate(request, username=username, password=password)

            if user is None:
                return Response({'detail': 'Invalid username or password.'}, status=status.HTTP_401_UNAUTHORIZED)

            # Check if email is verified
            try:
                email_verification = EmailVerification.objects.get(user=user)
                if not email_verification.verified:
                    return Response({'detail': 'Email not verified. Please verify your email.'},
                                    status=status.HTTP_400_BAD_REQUEST)
            except ObjectDoesNotExist:
                return Response({'detail': 'Email verification record not found. Please sign up again.'},
                                status=status.HTTP_400_BAD_REQUEST)

            # Generate or get token
            token, created = Token.objects.get_or_create(user=user)

            login(request, user)
            return Response({'token': token.key, 'username': user.username, 'detail': 'Login successful'},
                            status=status.HTTP_200_OK)

        except Exception as e:
            return Response({'detail': 'An error occurred while processing your request. Please try again later.'},
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class LogoutAPIView(APIView):
    authentication_classes = [SessionAuthentication, TokenAuthentication]
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_description="Logout the authenticated user.",
        responses={status.HTTP_200_OK: "Logout successful"}
    )
    def post(self, request):
        # Logout the user
        logout(request)
        return Response({'detail': 'Logout successful'}, status=status.HTTP_200_OK)
