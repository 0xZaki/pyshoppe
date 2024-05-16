from django.contrib.auth.models import AbstractUser
from django.db import models
from django.utils.translation import gettext_lazy as _
from .managers import CustomUserManager


# Create your models here.

class User(AbstractUser):
    username = None
    email = models.EmailField(_("email address"), unique=True)
    is_email_verified = models.BooleanField(_("email verified"), default=False)
    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = []

    objects = CustomUserManager()

    def __str__(self):
        return self.email
