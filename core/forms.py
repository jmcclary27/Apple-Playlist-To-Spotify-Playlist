from django import forms
from django.contrib.auth import authenticate
from django.core.exceptions import ValidationError
from .models import User

class LinkForm(forms.Form):
    url = forms.URLField(
        label='Paste your Apple Music playlist link',
        help_text='Example: https://music.apple.com/.../playlist/.../pl.xxxxx',
        widget=forms.URLInput(attrs={'placeholder': 'https://music.apple.com/...'})
    )

class SignupForm(forms.ModelForm):
    password = forms.CharField(widget=forms.PasswordInput)
    confirm_password = forms.CharField(widget=forms.PasswordInput)

    class Meta:
        model = User
        fields = ["email", "spotify_email", "password", "confirm_password"]

    def clean(self):
        data = super().clean()
        if data.get("password") != data.get("confirm_password"):
            raise ValidationError("Passwords do not match.")
        if data.get("email") and data.get("spotify_email"):
            if data["email"].strip().lower() != data["spotify_email"].strip().lower():
                raise ValidationError("Email must match your Spotify email exactly.")
        return data

    def save(self, commit=True):
        user = super().save(commit=False)
        user.username = self.cleaned_data["email"]
        user.set_password(self.cleaned_data["password"])
        user.is_active = True
        user.is_approved = False
        if commit:
            user.save()
        return user

class LoginForm(forms.Form):
    email = forms.EmailField()
    password = forms.CharField(widget=forms.PasswordInput)

    def clean(self):
        data = super().clean()
        email = data.get("email", "").strip().lower()
        pwd = data.get("password")
        user = authenticate(username=email, password=pwd)
        if not user:
            raise ValidationError("Invalid email or password.")
        data["user"] = user
        return data
