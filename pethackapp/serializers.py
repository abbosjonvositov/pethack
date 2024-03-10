from rest_framework import serializers
from django.contrib.auth.models import User
from .models import *


class UserSerializer(serializers.ModelSerializer):
    class Meta(object):
        model = User
        fields = '__all__'


class LoginSerializer(serializers.Serializer):
    username = serializers.CharField(
        max_length=150,
        help_text="Username of the user."
    )
    password = serializers.CharField(
        max_length=128,
        help_text="Password of the user."
    )


class SignupSerializer(serializers.Serializer):
    username = serializers.CharField(
        help_text="Username of the user."
    )
    password = serializers.CharField(
        help_text="Password of the user.",
        write_only=True
    )
    email = serializers.EmailField(
        help_text="Email address of the user."
    )

    def create(self, validated_data):
        pass


class EmailVerificationSerializer(serializers.Serializer):
    email = serializers.EmailField(
        help_text="Email address of the user."
    )
    code = serializers.CharField(
        max_length=4,
        help_text="Verification code sent to the user's email."
    )


class LogoutSerializer(serializers.Serializer):
    token = serializers.CharField(required=True, help_text="Authentication token in headers")
