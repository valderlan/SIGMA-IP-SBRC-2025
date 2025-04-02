from django.db import models
from django.db.models import IntegerField, CharField, FloatField, DateTimeField

class Whitelist(models.Model):
    ip_address = CharField(max_length=45, unique=True)
    country_code = CharField(max_length=3, null=True)
    city = CharField(max_length=255, null=True)
    abuseipdb_confidence_score = IntegerField(null=True)
    abuseipdb_total_reports = FloatField(null=True)
    abuseipdb_num_distinct_users = FloatField(null=True)
    virustotal_reputation = IntegerField(null=True)
    virustotal_harmless= IntegerField(null=True)
    virustotal_malicious = IntegerField(null=True)
    virustotal_suspicious = IntegerField(null=True)
    virustotal_undetected = IntegerField(null=True)
    ipvoid_detection_count  = IntegerField(null=True)
    risk_recommended_pulsedive = CharField(max_length=45, null=True)
    last_reported_at = DateTimeField(null=True, blank=True)
    timestamp_added = DateTimeField(auto_now_add=True, null=True)
    src_latitude = FloatField(null=True)
    src_longitude = FloatField(null=True)

    class Meta:
        db_table = 'whitelist'

    def __str__(self):
        return self.ip_address


class Tarpit(models.Model):
    ip_address = CharField(max_length=45, unique=True)
    country_code = CharField(max_length=3, null=True)
    city = CharField(max_length=255, null=True)
    abuseipdb_confidence_score = IntegerField(null=True)
    abuseipdb_total_reports = FloatField(null=True)
    abuseipdb_num_distinct_users = FloatField(null=True)
    virustotal_reputation = IntegerField(null=True)
    virustotal_harmless= IntegerField(null=True)
    virustotal_malicious = IntegerField(null=True)
    virustotal_suspicious = IntegerField(null=True)
    virustotal_undetected = IntegerField(null=True)
    ipvoid_detection_count  = IntegerField(null=True)
    risk_recommended_pulsedive = CharField(max_length=45, null=True)
    last_reported_at = DateTimeField(null=True, blank=True)
    timestamp_added = DateTimeField(auto_now_add=True, null=True)
    src_latitude = FloatField(null=True)
    src_longitude = FloatField(null=True)

    class Meta:
        db_table = 'tarpit'

    def __str__(self):
        return self.ip_address


class Blacklist(models.Model):
    ip_address = CharField(max_length=45, unique=True)
    country_code = CharField(max_length=3, null=True)
    city = CharField(max_length=255, null=True)
    abuseipdb_confidence_score = IntegerField(null=True)
    abuseipdb_total_reports = FloatField(null=True)
    abuseipdb_num_distinct_users = FloatField(null=True)
    virustotal_reputation = IntegerField(null=True)
    virustotal_harmless= IntegerField(null=True)
    virustotal_malicious = IntegerField(null=True)
    virustotal_suspicious = IntegerField(null=True)
    virustotal_undetected = IntegerField(null=True)
    ipvoid_detection_count  = IntegerField(null=True)
    risk_recommended_pulsedive = CharField(max_length=45, null=True)
    last_reported_at = DateTimeField(null=True, blank=True)
    timestamp_added = DateTimeField(auto_now_add=True, null=True)
    src_latitude = FloatField(null=True)
    src_longitude = FloatField(null=True)

    class Meta:
        db_table = 'blacklist'

    def __str__(self):
        return self.ip_address
    
class Suspect(models.Model):
    ip_address = CharField(max_length=45, unique=True)
    country_code = CharField(max_length=3, null=True)
    city = CharField(max_length=255, null=True)
    abuseipdb_confidence_score = IntegerField(null=True)
    abuseipdb_total_reports = FloatField(null=True)
    abuseipdb_num_distinct_users = FloatField(null=True)
    virustotal_reputation = IntegerField(null=True)
    virustotal_harmless= IntegerField(null=True)
    virustotal_malicious = IntegerField(null=True)
    virustotal_suspicious = IntegerField(null=True)
    virustotal_undetected = IntegerField(null=True)
    ipvoid_detection_count  = IntegerField(null=True)
    risk_recommended_pulsedive = CharField(max_length=45, null=True)
    last_reported_at = DateTimeField(null=True, blank=True)
    timestamp_added = DateTimeField(auto_now_add=True, null=True)
    src_latitude = FloatField(null=True)
    src_longitude = FloatField(null=True)

    class Meta:
        db_table = 'suspect'

    def __str__(self):
        return self.ip_address

