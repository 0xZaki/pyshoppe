from django.urls import path
from rest_framework_simplejwt.views import TokenRefreshView

from .views import (
    RegisterView,
    ActivateAccountView,
    CustomTokenObtainPairView,
    ResetPasswordView,
    ResetPasswordConfirmView,
    ChangePasswordView
)

urlpatterns = [
    # JWT Authentication Endpoints
    path('api/v1/token/', CustomTokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('api/v1/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),

    # User Registration and Activation Endpoints
    path('api/accounts/register/', RegisterView.as_view(), name='register'),
    path('accounts/activate/<uidb64>/<token>/', ActivateAccountView.as_view(), name='activate'),

    # Password Reset Endpoints
    path('api/accounts/reset-password/', ResetPasswordView.as_view(), name='reset-password'),
    path('accounts/reset-password/confirm/<uidb64>/<token>/', ResetPasswordConfirmView.as_view(),
         name='reset-password-confirm'),

    # Password Change Endpoint
    path('api/accounts/change-password/', ChangePasswordView.as_view(), name='change-password'),
]
