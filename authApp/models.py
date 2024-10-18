from django.db import models


class User(models.Model):
    username = models.CharField(max_length=100, unique=True)
    password = models.CharField(max_length=100)
    email = models.CharField(max_length=100, unique=True)
    refreshToken = models.TextField(blank=True, null=True)
    accessToken = models.TextField(blank=True, null=True)
    accessTokenExpires = models.DateTimeField(blank=True, null=True)
    accessTokenCreated = models.DateTimeField(blank=True, null=True)
# Create your models here.
