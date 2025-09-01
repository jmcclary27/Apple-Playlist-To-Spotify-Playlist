"""
URL configuration for config project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.0/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path
from core import views as core_views

urlpatterns = [
    path("", core_views.index, name="index"),
    path("health", core_views.health, name="health"),
    path("preview", core_views.preview, name="preview"),

    # Spotify OAuth
    path("auth/spotify/login", core_views.spotify_login, name="spotify_login"),
    path("auth/spotify/callback", core_views.spotify_callback, name="spotify_callback"),

    # Simple acceptance-test endpoint
    path("me", core_views.me, name="me"),
    path("conversion/<str:cid>", core_views.conversion_detail, name="conversion_detail"),
    
    path('admin/', admin.site.urls),
    path('upload/', core_views.upload_link, name='upload'),
    path('match/', core_views.match_view, name='match'),
    path("debug/status", core_views.debug_status),
]
