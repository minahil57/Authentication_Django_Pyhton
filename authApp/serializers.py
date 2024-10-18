from rest_framework import serializers
from .models import User
from django.contrib.auth.hashers import make_password


class LoginSerializer(serializers.Serializer):
    username = serializers.CharField(max_length=100)
    password = serializers.CharField(max_length=100)
    def validate(self, data):
        if "username" not in data:
            raise serializers.ValidationError("username is required")
        if "password" not in data:
            raise serializers.ValidationError("password is required")

        return data



    

class RegisterSerializer( serializers.ModelSerializer ):
    password = serializers.CharField(write_only=True)
    class Meta:
        model = User
        fields = ['username', 'email', 'password']

    def create(self, validated_data):
        # Create a new user instance and set the password properly
        user = User.objects.create(
            username=validated_data['username'],
            email=validated_data['email'],
            password=make_password(validated_data['password'])
        )
        user.save()
        return user