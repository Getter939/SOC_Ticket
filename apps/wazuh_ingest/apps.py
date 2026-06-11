from django.apps import AppConfig


class WazuhIngestConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'apps.wazuh_ingest'
    verbose_name = 'Wazuh Alert Ingestion'
