# core/decorators.py
from django.http import HttpResponseForbidden

def approved_required(view_func):
    def _wrapped(request, *args, **kwargs):
        if not request.user.is_authenticated:
            return HttpResponseForbidden("Please log in.")
        if not request.user.is_approved:
            return HttpResponseForbidden("Your account is pending approval.")
        return view_func(request, *args, **kwargs)
    return _wrapped
