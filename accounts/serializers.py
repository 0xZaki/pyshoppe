import django.contrib.auth.password_validation as validators
from django.contrib.auth import get_user_model
from rest_framework import serializers

User = get_user_model()


class UserRegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)
    password2 = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = ['email', 'password', 'password2', 'first_name', 'last_name']

    def validate_password(self, value):
        validators.validate_password(value)
        return value

    def validate(self, data):
        if data['password'] != data.get('password2'):
            raise serializers.ValidationError({'password': 'Passwords do not match.'})
        return data

    def create(self, validated_data):
        user = User.objects.create_user(
            email=validated_data['email'],
            password=validated_data['password'],
            first_name=validated_data.get('first_name', ''),
            last_name=validated_data.get('last_name', '')
        )
        return user


class ResetPasswordConfirmInputSerializer(serializers.Serializer):
    password = serializers.CharField()
    password2 = serializers.CharField()

    def validate_password(self, value):
        validators.validate_password(value)
        return value

    def validate(self, data):
        if data['password'] != data.get('password2'):
            raise serializers.ValidationError({'password': 'Passwords do not match.'})
        return data


class ChangePasswordInputSerializer(serializers.Serializer):
    old_password = serializers.CharField()
    new_password = serializers.CharField()
    new_password2 = serializers.CharField()

    def validate_new_password(self, value):
        validators.validate_password(value)
        return value

    def validate(self, data):
        if data['new_password'] != data.get('new_password2'):
            raise serializers.ValidationError({'new_password': 'Passwords do not match.'})
        return data
