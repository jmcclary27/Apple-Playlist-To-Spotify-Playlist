# core/admin.py
from django.contrib import admin, messages
from django.utils import timezone
from django.core.mail import send_mail, EmailMessage
from django.conf import settings
from .models import User

@admin.register(User)
class UserAdmin(admin.ModelAdmin):
    list_display = ("email", "is_approved", "requested_at", "approved_at")
    search_fields = ("email",)
    actions = ["approve_and_notify"]

    @admin.action(description="Approve selected users and send 'ready' email")
    def approve_and_notify(self, request, queryset):
        updated = 0
        for user in queryset:
            if not user.is_approved:
                user.is_approved = True
                user.approved_at = timezone.now()
                user.save(update_fields=["is_approved", "approved_at"])

                # Use EmailMessage to set headers (Reply-To)
                msg = EmailMessage(
                    subject="Your account is ready",
                    body=(
                        "Hi,\n\nYour account has been approved. "
                        "You can now log in and upload your playlist.\n\nThanks!"
                    ),
                    from_email=settings.DEFAULT_FROM_EMAIL,
                    to=[user.email],
                    headers={"Reply-To": settings.DEFAULT_FROM_EMAIL},
                )
                msg.send(fail_silently=False)

                updated += 1
        self.message_user(request, f"Approved + notified: {updated}", messages.SUCCESS)
