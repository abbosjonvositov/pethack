# views.py
from django.shortcuts import get_object_or_404
from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login, logout
from django.core.mail import send_mail
from rest_framework.authentication import SessionAuthentication, TokenAuthentication
from rest_framework.permissions import IsAuthenticated
from django.conf import settings
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.authtoken.models import Token
from .models import EmailVerification
import random


class SignupAPIView(APIView):
    def post(self, request):
        email = request.data.get('email')
        username = request.data.get('username')
        password = request.data.get('password')

        if not email or not username or not password:
            return Response({'detail': 'Email, username, and password are required.'},
                            status=status.HTTP_400_BAD_REQUEST)

        # Create user
        user = User.objects.create_user(username=username, email=email, password=password)

        # Generate a random verification code with 4 digits
        code = ''.join([str(random.randint(0, 9)) for _ in range(4)])  # Example code generation

        # Send the code via email
        send_mail(
            'Verification Code',
            f'Your verification code is: {code}',
            settings.EMAIL_HOST_USER,
            [email],
            fail_silently=False,
        )

        # Store the verification code
        EmailVerification.objects.create(user=user, code=code)

        # Create token for the user
        token = Token.objects.create(user=user)

        return Response({'detail': 'Signup successful. Please verify your email.', 'token': token.key},
                        status=status.HTTP_201_CREATED)


class VerifyEmailAPIView(APIView):
    authentication_classes = [SessionAuthentication, TokenAuthentication]
    permission_classes = [IsAuthenticated]

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
    def post(self, request):

        username = request.data.get('username')
        password = request.data.get('password')

        user = authenticate(request, username=username, password=password)
        print(user)
        if user is not None:
            # Check if email is verified
            email_verification = get_object_or_404(EmailVerification, user=user)
            if not email_verification.verified:
                return Response({'detail': 'Email not verified. Please verify your email.'},
                                status=status.HTTP_400_BAD_REQUEST)

            # Generate or get token
            token, created = Token.objects.get_or_create(user=user)

            login(request, user)
            return Response({'token': token.key, 'detail': 'Login successful'}, status=status.HTTP_200_OK)
        else:
            return Response({'detail': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)


class LogoutAPIView(APIView):
    authentication_classes = [SessionAuthentication, TokenAuthentication]
    permission_classes = [IsAuthenticated]

    def post(self, request):
        # Logout the user
        logout(request)
        return Response({'detail': 'Logout successful'}, status=status.HTTP_200_OK)
