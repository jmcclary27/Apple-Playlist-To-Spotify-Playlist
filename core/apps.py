from django.apps import AppConfig

class CoreConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = "core"

    def ready(self):
        # Don’t crash the app if Mongo isn’t configured yet
        try:
            from .mongo import ensure_indexes
            ensure_indexes()
        except Exception:
            pass
