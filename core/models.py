# Create your models here.
# models.py
from django.db import models
class SpotifyAccessRequest(models.Model):
    email = models.EmailField()
    username = models.CharField(max_length=120, blank=True)
    org = models.CharField(max_length=120, blank=True)
    notes = models.TextField(blank=True)
    approved = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
