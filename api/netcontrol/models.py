from django.db import models

class Whitelist(models.Model):
    ip_address = models.CharField(max_length=45, unique=True)
    country_code = models.CharField(max_length=3, null=True)
    city = models.CharField(max_length=255, null=True)
    # Parte do abuse
    abuse_confidence_score = models.IntegerField(null=True)
    total_reports = models.FloatField(null=True)
    num_distinct_users = models.FloatField(null=True)
    # Parte do virustotal
    virustotal_reputation = models.IntegerField(null=True)
    harmless_virustotal = models.IntegerField(null=True)
    malicious_virustotal = models.IntegerField(null=True)
    suspicious_virustotal = models.IntegerField(null=True)
    undetected_virustotal = models.IntegerField(null=True)
    # Parte do IPVoid
    ipvoid_detection_count  = models.IntegerField(null=True)
    # Parte do Pulsedive
    risk_recommended_pulsedive = models.CharField(max_length=45, null=True)
    # Resto normal
    last_reported_at = models.DateTimeField(null=True, blank=True)
    src_longitude = models.FloatField(null=True)
    src_latitude = models.FloatField(null=True)
    timestamp_added = models.DateTimeField(auto_now_add=True, null=True)

    class Meta:
        db_table = 'whitelist'

    def __str__(self):
        return self.ip_address


class Tarpit(models.Model):
    ip_address = models.CharField(max_length=45, unique=True)
    country_code = models.CharField(max_length=3, null=True)
    city = models.CharField(max_length=255, null=True)
    # Parte do abuse
    abuse_confidence_score = models.IntegerField(null=True)
    total_reports = models.FloatField(null=True)
    num_distinct_users = models.FloatField(null=True)
    # Parte do virustotal
    virustotal_reputation = models.IntegerField(null=True)
    harmless_virustotal = models.IntegerField(null=True)
    malicious_virustotal = models.IntegerField(null=True)
    suspicious_virustotal = models.IntegerField(null=True)
    undetected_virustotal = models.IntegerField(null=True)
    # Parte do IPVoid
    ipvoid_detection_count = models.IntegerField(null=True)
    # Parte do Pulsedive
    risk_recommended_pulsedive = models.CharField(max_length=45, null=True)
    # Resto normal
    last_reported_at = models.DateTimeField(null=True, blank=True)
    timestamp_added = models.DateTimeField(auto_now_add=True, null=True)
    src_longitude = models.FloatField(null=True)
    src_latitude = models.FloatField(null=True)

    class Meta:
        db_table = 'tarpit'

    def __str__(self):
        return self.ip_address


class Blacklist(models.Model):
    ip_address = models.CharField(max_length=45, unique=True)
    country_code = models.CharField(max_length=3, null=True)
    city = models.CharField(max_length=255, null=True)
    # Parte do abuse
    abuse_confidence_score = models.IntegerField(null=True)
    total_reports = models.FloatField(null=True)
    num_distinct_users = models.FloatField(null=True)
    # Parte do virustotal
    virustotal_reputation = models.IntegerField(null=True)
    harmless_virustotal = models.IntegerField(null=True)
    malicious_virustotal = models.IntegerField(null=True)
    suspicious_virustotal = models.IntegerField(null=True)
    undetected_virustotal = models.IntegerField(null=True)
    # Parte do IPVoid
    ipvoid_detection_count  = models.IntegerField(null=True)
    # Parte do Pulsedive
    risk_recommended_pulsedive = models.CharField(max_length=45, null=True)
    # Resto normal
    last_reported_at = models.DateTimeField(null=True, blank=True)
    timestamp_added = models.DateTimeField(auto_now_add=True, null=True)
    src_latitude = models.FloatField(null=True)
    src_longitude = models.FloatField(null=True)

    class Meta:
        db_table = 'blacklist'

    def __str__(self):
        return self.ip_address 
