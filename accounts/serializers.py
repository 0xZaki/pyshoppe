from django.contrib.auth import get_user_model
from rest_framework import serializers

User = get_user_model()


class UserRegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)
    password2 = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = ['email', 'password', 'password2', 'first_name', 'last_name']

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
