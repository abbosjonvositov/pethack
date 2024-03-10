from django.urls import path
from rest_framework.schemas import get_schema_view
from django.views.generic import TemplateView
from .views import *
from drf_yasg.views import get_schema_view
from drf_yasg import openapi

schema_view = get_schema_view(
    openapi.Info(
        title="3W PetHack Project",
        default_version='v1',
        description="TEST",
        terms_of_service="https://www.google.com/policies/terms/",
        contact=openapi.Contact(email="abbosjonvostiov@example.com"),
        license=openapi.License(name="BSD License"),
    ),
    public=True,
)

urlpatterns = [
    path('signup/', SignupAPIView.as_view(), name='signup'),
    path('verify-email/', VerifyEmailAPIView.as_view(), name='verify-email'),
    path('login/', LoginAPIView.as_view(), name='login'),
    path('logout/', LogoutAPIView.as_view(), name='logout'),
    path('swagger/', schema_view.with_ui('swagger', cache_timeout=0), name='schema-swagger-ui'),

]
