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
from rest_framework_simplejwt.views import TokenObtainPairView

from .serializers import UserRegisterSerializer
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

    class ResetPasswordConfirmInputSerializer(serializers.Serializer):
        password = serializers.CharField()
        password2 = serializers.CharField()

        def validate(self, data):
            if data['password'] != data.get('password2'):
                raise serializers.ValidationError({'password': 'Passwords do not match.'})
            return data

    @extend_schema(request=ResetPasswordConfirmInputSerializer)
    def post(self, request, uidb64, token):
        serializer = self.ResetPasswordConfirmInputSerializer(data=request.data)
        if serializer.is_valid():
            uid = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=uid)
            if account_activation_token.check_token(user, token):
                user.set_password(serializer.validated_data['password'])
                user.save()
                return Response({'detail': 'Your password has been successfully reset.'})
        return Response({'detail': 'Invalid reset password link.'}, status=status.HTTP_400_BAD_REQUEST)


class ChangePasswordView(APIView):
    class ChangePasswordInputSerializer(serializers.Serializer):
        old_password = serializers.CharField()
        new_password = serializers.CharField()
        new_password2 = serializers.CharField()

        def validate(self, data):
            if data['new_password'] != data.get('new_password2'):
                raise serializers.ValidationError({'new_password': 'Passwords do not match.'})
            return data

    @extend_schema(request=ChangePasswordInputSerializer)
    def post(self, request):
        serializer = self.ChangePasswordInputSerializer(data=request.data)
        if serializer.is_valid():
            user = request.user
            if user.check_password(serializer.validated_data['old_password']):
                user.set_password(serializer.validated_data['new_password'])
                user.save()
                return Response({'detail': 'Your password has been successfully changed.'})
            return Response({'detail': 'Invalid old password.'}, status=status.HTTP_400_BAD_REQUEST)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
