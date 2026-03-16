from django.apps import AppConfig


class NetcontrolConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'apps.netcontrol'

    def ready(self):
        from apps.netcontrol.services.logging import setup_logging

        setup_logging()
