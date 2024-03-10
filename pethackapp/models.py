from django.db import models
from django.db import models
from django.contrib.auth.models import User
from rest_framework.authtoken.models import Token


# Create your models here.
class EmailVerification(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    code = models.CharField(max_length=4)
    verified = models.BooleanField(default=False)
