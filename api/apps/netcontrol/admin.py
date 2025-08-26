from django.contrib import admin
from .models import Blacklist, Whitelist, Analysis, Suspect


class BlacklistAdmin(admin.ModelAdmin):
    search_fields = [
        "id",
        "ip_address",
        "country_code",
        "city",
        "abuseipdb_confidence_score",
        "last_reported_at",
        "timestamp_added",
    ]
    list_display = [
        "id",
        "ip_address",
        "country_code",
        "city",
        "abuseipdb_confidence_score",
        "last_reported_at",
        "timestamp_added",
    ]
    list_filter = ["country_code", "last_reported_at", "timestamp_added"]


class WhitelistAdmin(admin.ModelAdmin):
    search_fields = ["id", "ip_address"]
    list_display = [
        "id",
        "ip_address",
        "country_code",
        "last_reported_at",
        "timestamp_added",
    ]
    list_filter = ["country_code", "last_reported_at", "timestamp_added"]


class AnalysisAdmin(admin.ModelAdmin):
    search_fields = ["id", "ip_address", "country_code"]
    list_display = ["id", "ip_address", "country_code"]
    list_filter = ["id", "ip_address", "last_reported_at"]


class SuspectAdmin(admin.ModelAdmin):
    search_fields = [
        "id",
        "ip_address",
        "country_code",
        "city",
        "abuseipdb_confidence_score",
        "last_reported_at",
        "timestamp_added",
    ]
    list_display = [
        "id",
        "ip_address",
        "country_code",
        "city",
        "abuseipdb_confidence_score",
        "last_reported_at",
        "timestamp_added",
    ]
    list_filter = ["country_code", "last_reported_at", "timestamp_added"]


admin.site.site_header = "NetControl Administration"
admin.site.register(Blacklist, BlacklistAdmin)
admin.site.register(Whitelist, WhitelistAdmin)
admin.site.register(Analysis, AnalysisAdmin)
admin.site.register(Suspect, SuspectAdmin)
