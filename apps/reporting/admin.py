"""Admin for the reporting layer.

Only ``DimSeverityMap`` is registered — its whole purpose is to let the SOC lead
tune severity band thresholds (and onboard new sources) without a deploy. The
fact/aggregate objects are read-only views and are not exposed here.
"""
from django.contrib import admin

from .models import DimSeverityMap


@admin.register(DimSeverityMap)
class DimSeverityMapAdmin(admin.ModelAdmin):
    list_display = ('source_system', 'min_value', 'max_value', 'canonical_band')
    list_filter = ('source_system', 'canonical_band')
    list_editable = ('min_value', 'max_value', 'canonical_band')
    ordering = ('source_system', '-min_value')
