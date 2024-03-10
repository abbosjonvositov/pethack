from django.urls import path
from .views import *

urlpatterns = [
    path('signup/', SignupAPIView.as_view(), name='signup'),
    path('verify-email/', VerifyEmailAPIView.as_view(), name='verify-email'),
    path('login/', LoginAPIView.as_view(), name='login'),
    path('logout/', LogoutAPIView.as_view(), name='logout'),
]
