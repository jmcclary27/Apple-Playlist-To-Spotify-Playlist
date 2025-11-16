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
# config/urls.py
from django.contrib import admin
from django.urls import path
from core import views as core_views
from core import views_auth

urlpatterns = [
    # Landing → Upload
    path("", core_views.landing, name="landing"),
    path("upload/", core_views.upload_link, name="upload"),

    # Matching job flow
    path("match/start", core_views.match_start, name="match_start"),  # POST → {job_id}
    path("match/progress/<str:job_id>", core_views.match_progress_page, name="match_progress_page"),  # GET page
    path("match/results/<str:job_id>", core_views.match_results_page, name="match_results_page"),  # GET page
    path("api/match/report/<str:job_id>.csv", core_views.match_report_csv, name="match_report_csv"),  # GET CSV

    # Spotify OAuth
    path("auth/spotify/callback", core_views.spotify_callback, name="spotify_callback"),

    # Optional utilities
    path("me", core_views.me, name="me"),
    path("conversion/<str:cid>", core_views.conversion_detail, name="conversion_detail"),
    path("debug/status", core_views.debug_status, name="debug_status"),
    path("match/run/<str:job_id>", core_views.match_run, name="match_run"),

    path("admin/", admin.site.urls),
]
