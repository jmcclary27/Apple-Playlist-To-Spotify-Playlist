# Create your models here.
# models.py
from django.db import models
from django.contrib.auth.models import AbstractUser

class SpotifyAccessRequest(models.Model):
    email = models.EmailField()
    username = models.CharField(max_length=120, blank=True)
    org = models.CharField(max_length=120, blank=True)
    notes = models.TextField(blank=True)
    approved = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

class User(AbstractUser):
    email = models.EmailField(unique=True)
    is_approved = models.BooleanField(default=False)
    spotify_email = models.EmailField(help_text="Must match the email used on Spotify.")
    requested_at = models.DateTimeField(auto_now_add=True)
    approved_at = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        return self.email
