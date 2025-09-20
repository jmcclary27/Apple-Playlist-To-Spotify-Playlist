# core/views_auth.py
from django.http import JsonResponse
from django.views.decorators.http import require_POST
from django.views.decorators.csrf import ensure_csrf_cookie
from django.contrib.auth import login, logout
from django.core.mail import EmailMessage
from django.conf import settings

from .forms import SignupForm, LoginForm

@require_POST
def signup_api(request):
    form = SignupForm(request.POST)
    if not form.is_valid():
        return JsonResponse({"ok": False, "errors": form.errors}, status=400)

    user = form.save()

    # Email YOU the new signup details for Spotify tester intake
    admin_body = (
        "New signup awaiting manual Spotify tester approval:\n\n"
        f"User ID: {user.id}\n"
        f"Email: {user.email}\n"
        f"Spotify Email: {user.spotify_email}\n"
        f"Requested At: {user.requested_at}\n\n"
        f"Admin link: /admin/core/user/{user.id}/change/\n"
    )
    admin_msg = EmailMessage(
        subject="[Action Needed] New user waiting for Spotify tester approval",
        body=admin_body,
        from_email=settings.DEFAULT_FROM_EMAIL,
        to=[settings.AUTH_NOTIFIER_EMAIL],
        headers={"Reply-To": settings.DEFAULT_FROM_EMAIL},
    )
    admin_msg.send(fail_silently=False)

    return JsonResponse({
        "ok": True,
        "status": "pending",
        "message": "We’re authenticating your account. You’ll get an email when it’s ready."
    })

@require_POST
def login_api(request):
    form = LoginForm(request.POST)
    if not form.is_valid():
        return JsonResponse({"ok": False, "errors": form.errors}, status=400)

    user = form.cleaned_data["user"]
    login(request, user)

    if not user.is_approved:
        return JsonResponse({"ok": True, "status": "pending"})

    return JsonResponse({"ok": True, "status": "approved"})

@require_POST
def logout_api(request):
    logout(request)
    return JsonResponse({"ok": True})

@ensure_csrf_cookie
def auth_status(request):
    u = request.user if request.user.is_authenticated else None
    if not u:
        return JsonResponse({"authenticated": False})
    return JsonResponse({
        "authenticated": True,
        "approved": bool(u.is_approved),
        "email": u.email
    })
