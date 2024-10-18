import datetime
import os

from django.shortcuts import render
from django.utils import timezone
from django.contrib.auth import authenticate
from django.contrib.auth.hashers import check_password
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.authtoken.models import Token
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.tokens import RefreshToken

from .serializers import LoginSerializer,RegisterSerializer
from .models import User


class LoginApi(APIView):

    def post(self, request):
        print("Called")
        data = request.data

        serializer = LoginSerializer(data=data)
        print("serializer", serializer)

        if serializer.is_valid():
            print("valid")

            username = serializer.validated_data.get('username')
            password = serializer.validated_data.get('password')

            # Fetch user from the database
            user = User.objects.filter(username=username).first()
            
            if user:
                print("user", user)

                # Check the password manually
                if check_password(password, user.password):
                    print("password", password)

                    # Generate JWT tokens using the user object
                    jwt_token = RefreshToken.for_user(user)

                    # Update the user object with token info
                    user.refreshToken = str(jwt_token)
                    user.accessToken = str(jwt_token.access_token)
                    
                    access_token_expires = datetime.datetime.fromtimestamp(jwt_token['exp'], tz=datetime.timezone.utc)
                    access_token_created = datetime.datetime.fromtimestamp(jwt_token['iat'], tz=datetime.timezone.utc)

                    # Update the user's token fields in the database
                    User.objects.filter(username=username).update(
                        refreshToken=user.refreshToken,
                        accessToken=user.accessToken,
                        accessTokenExpires=access_token_expires,
                        accessTokenCreated=access_token_created
                    )

                    # Re-fetch the user to access updated fields
                    updated_user = User.objects.get(username=username)

                    return Response(
                        {
                            "message": "Login successful",
                            "data": {
                                'created': access_token_created,
                                'expires': access_token_expires,
                                'refresh': updated_user.refreshToken,
                                'access': updated_user.accessToken,
                            }
                        },
                        status=status.HTTP_200_OK
                    )
                else:
                    return Response({"details": "Invalid password"}, status=status.HTTP_401_UNAUTHORIZED)
            else:
                return Response({"message": "Invalid login credentials"}, status=status.HTTP_401_UNAUTHORIZED)

        # Handle invalid serializer data
        return Response(
            {
                "message": "Invalid data",
                "errors": serializer.errors
            },
            status=status.HTTP_400_BAD_REQUEST
        )


class RegistrationView(APIView):

    def post(self, request):

        serializer = RegisterSerializer(data=request.data)
        

        if serializer.is_valid():

            user = serializer.save()  # Create the user
            

            return Response({

                "message": "Registration successful",

                "data": {

                    

                    "username": user.username,

                    "email": user.email

                }

            }, status=status.HTTP_201_CREATED)
        

        return Response({

            "message": "Registration failed",

            "errors": serializer.errors

        }, status=status.HTTP_400_BAD_REQUEST)

