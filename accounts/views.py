from urllib.parse import urlencode

import requests
from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.urls import reverse
from django.utils.encoding import force_bytes, force_str
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from drf_spectacular.utils import extend_schema
from rest_framework import status, serializers
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import AccessToken, RefreshToken
from rest_framework_simplejwt.views import TokenObtainPairView

from accounts.utils import get_state, validate_state
from .serializers import UserRegisterSerializer, ResetPasswordConfirmInputSerializer, ChangePasswordInputSerializer
from .tokens import account_activation_token

User = get_user_model()


class RegisterView(APIView):
    authentication_classes = ()
    permission_classes = ()

    @extend_schema(request=UserRegisterSerializer, responses={201: UserRegisterSerializer})
    def post(self, request, *args, **kwargs):
        serializer = UserRegisterSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            user.save()
            self.send_activation_email(request, user)
            return Response({'detail': 'Check your email for activation link.'}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def send_activation_email(self, request, user):
        subject = 'Activate Your Account'
        token = account_activation_token.make_token(user)
        uid = urlsafe_base64_encode(force_bytes(user.pk))
        activation_link = request.build_absolute_uri(reverse('activate', kwargs={'uidb64': uid, 'token': token}))
        message = render_to_string('accounts/activation_email.html', {
            'user': user,
            'activation_link': activation_link,
        })
        send_mail(subject, message, settings.EMAIL_HOST_USER, [user.email])


class ActivateAccountView(APIView):
    authentication_classes = ()
    permission_classes = ()

    def get(self, request, uidb64, token):
        try:
            uid = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=uid)
        except User.DoesNotExist:
            user = None

        if user is not None and account_activation_token.check_token(user, token):
            user.is_email_verified = True
            user.save()
            # TODO: Redirect to a Frontend URL
            return Response({'detail': 'Your account has been successfully activated.'}, status=status.HTTP_200_OK)
        else:
            return Response({'detail': 'Invalid activation link.'}, status=status.HTTP_400_BAD_REQUEST)


class CustomTokenObtainPairView(TokenObtainPairView):
    authentication_classes = ()
    permission_classes = ()

    def post(self, request, *args, **kwargs):
        response = super().post(request, *args, **kwargs)
        user = User.objects.get(email=request.data['email'])
        if not user.is_email_verified:
            return Response({'detail': 'Email is not verified.'}, status=status.HTTP_403_FORBIDDEN)
        return response


class ResetPasswordView(APIView):
    authentication_classes = ()
    permission_classes = ()

    class ResetPasswordInputSerializer(serializers.Serializer):
        email = serializers.EmailField()

    @extend_schema(request=ResetPasswordInputSerializer)
    def post(self, request):
        serializer = self.ResetPasswordInputSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            try:
                user = User.objects.get(email=email)
                self.send_reset_password_email(request, user)
            except User.DoesNotExist:
                pass

        return Response({'detail': 'If the email exists in our system, you will receive a password reset link.'})

    def send_reset_password_email(self, request, user):
        subject = 'Reset Your Password'
        token = account_activation_token.make_token(user)
        uid = urlsafe_base64_encode(force_bytes(user.pk))
        reset_password_link = request.build_absolute_uri(
            reverse('reset-password-confirm', kwargs={'uidb64': uid, 'token': token}))
        message = render_to_string('accounts/reset_password_email.html', {
            'user': user,
            'reset_password_link': reset_password_link,
        })
        send_mail(subject, message, settings.EMAIL_HOST_USER, [user.email])


class ResetPasswordConfirmView(APIView):
    authentication_classes = ()
    permission_classes = ()

    @extend_schema(request=ResetPasswordConfirmInputSerializer)
    def post(self, request, uidb64, token):
        serializer = ResetPasswordConfirmInputSerializer(data=request.data)
        if serializer.is_valid():
            uid = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=uid)
            if account_activation_token.check_token(user, token):
                user.set_password(serializer.validated_data['password'])
                user.save()
                return Response({'detail': 'Your password has been successfully reset.'})
        return Response({'detail': 'Invalid reset password link.'}, status=status.HTTP_400_BAD_REQUEST)


class ChangePasswordView(APIView):

    @extend_schema(request=ChangePasswordInputSerializer)
    def post(self, request):
        serializer = ChangePasswordInputSerializer(data=request.data)
        if serializer.is_valid():
            user = request.user
            if user.check_password(serializer.validated_data['old_password']):
                user.set_password(serializer.validated_data['new_password'])
                user.save()
                return Response({'detail': 'Your password has been successfully changed.'})
            return Response({'detail': 'Invalid old password.'}, status=status.HTTP_400_BAD_REQUEST)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class GoogleLoginView(APIView):
    authentication_classes = ()
    permission_classes = ()

    class GoogleLoginInputSerializer(serializers.Serializer):
        code = serializers.CharField()
        state = serializers.CharField()

    def get(self, request):
        params = {
            "client_id": settings.GOOGLE_CLIENT_ID,
            "redirect_uri": 'http://localhost:8000/accounts/google/callback/',  # TODO: Change this to your frontend URL
            "response_type": "code",
            "scope": "email profile",
            "state": get_state(),
        }
        redirect_url = f"{settings.GOOGLE_AUTH_URL}?{urlencode(params)}"
        return Response({'redirect_url': redirect_url})

    @extend_schema(request=GoogleLoginInputSerializer)
    def post(self, request):
        serializer = self.GoogleLoginInputSerializer(data=request.data)
        if serializer.is_valid():
            code = serializer.validated_data['code']
            state = serializer.validated_data['state']
            if not validate_state(state):
                return Response({'detail': 'Invalid state parameter'}, status=status.HTTP_400_BAD_REQUEST)
            token_url = "https://oauth2.googleapis.com/token"
            data = {
                "client_id": settings.GOOGLE_CLIENT_ID,
                "client_secret": settings.GOOGLE_CLIENT_SECRET,
                # TODO: Change this to your frontend URL
                "redirect_uri": 'http://localhost:8000/accounts/google/callback/',
                "code": code,
                "grant_type": "authorization_code",
            }
            response = requests.post(token_url, data=data)
            token_data = response.json()
            access_token = token_data.get("access_token")
            if access_token:
                user_info_url = "https://www.googleapis.com/oauth2/v1/userinfo"
                headers = {"Authorization": f"Bearer {access_token}"}
                user_info_response = requests.get(user_info_url, headers=headers)
                user_info = user_info_response.json()
                user, created = User.objects.get_or_create(email=user_info['email'])
                if created:
                    user.first_name = user_info['given_name']
                    user.last_name = user_info['family_name']
                    user.save()

                return Response(
                    {'access': str(AccessToken.for_user(user)), 'refresh': str(RefreshToken.for_user(user))})
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
