from django.db.models import IntegerField, CharField, FloatField, DateTimeField, Model
from django.forms.models import model_to_dict

class Whitelist(Model):
    ip_address = CharField(max_length=45, unique=True)
    country_code = CharField(max_length=3, null=True)
    city = CharField(max_length=255, null=True)
    abuseipdb_confidence_score = IntegerField(null=True)
    abuseipdb_total_reports = FloatField(null=True)
    abuseipdb_num_distinct_users = FloatField(null=True)
    abuseipdb_recent_reports_count = IntegerField(null=True)
    abuseipdb_last_reported_at = DateTimeField(null=True, blank=True)
    abuseipdb_country_code = CharField(max_length=3, null=True)
    abuseipdb_is_whitelisted = FloatField(null=True)
    apivoid_risk_score = IntegerField(null=True)
    apivoid_blacklists_engines_count = IntegerField(null=True)
    apivoid_blacklists_detection_rate = FloatField(null=True)
    apivoid_country_name = CharField(null=True)
    risk_recommended_pulsedive = CharField(max_length=45, null=True)
    stamp_updated_pulsedive = DateTimeField(null=True)
    unknown_pulsedive = IntegerField(null=True)
    none_pulsedive = IntegerField(null=True)
    low_pulsedive = IntegerField(null=True)
    medium_pulsedive = IntegerField(null=True)
    high_pulsedive = IntegerField(null=True)
    critical_pulsedive = IntegerField(null=True)
    virustotal_reputation = IntegerField(null=True)
    virustotal_harmless= IntegerField(null=True)
    virustotal_malicious = IntegerField(null=True)
    virustotal_suspicious = IntegerField(null=True)
    virustotal_undetected = IntegerField(null=True)
    virustotal_last_modification_date = DateTimeField(null=True)
    timestamp_added = DateTimeField(auto_now_add=True, null=True)
    src_latitude = FloatField(null=True)
    src_longitude = FloatField(null=True)

    class Meta:
        db_table = 'allowlist'

    def __str__(self):
        return self.ip_address


class Analysis(Model):
    ip_address = CharField(max_length=45, unique=True)
    country_code = CharField(max_length=3, null=True)
    city = CharField(max_length=255, null=True)
    abuseipdb_confidence_score = IntegerField(null=True)
    abuseipdb_total_reports = FloatField(null=True)
    abuseipdb_num_distinct_users = FloatField(null=True)
    abuseipdb_recent_reports_count = IntegerField(null=True)
    abuseipdb_last_reported_at = DateTimeField(null=True, blank=True)
    abuseipdb_country_code = CharField(max_length=3, null=True)
    abuseipdb_is_whitelisted = FloatField(null=True)
    apivoid_risk_score = IntegerField(null=True)
    apivoid_blacklists_engines_count = IntegerField(null=True)
    apivoid_blacklists_detection_rate = FloatField(null=True)
    apivoid_country_name = CharField(null=True)
    risk_recommended_pulsedive = CharField(max_length=45, null=True)
    stamp_updated_pulsedive = DateTimeField(null=True)
    unknown_pulsedive = IntegerField(null=True)
    none_pulsedive = IntegerField(null=True)
    low_pulsedive = IntegerField(null=True)
    medium_pulsedive = IntegerField(null=True)
    high_pulsedive = IntegerField(null=True)
    critical_pulsedive = IntegerField(null=True)
    virustotal_reputation = IntegerField(null=True)
    virustotal_harmless= IntegerField(null=True)
    virustotal_malicious = IntegerField(null=True)
    virustotal_suspicious = IntegerField(null=True)
    virustotal_undetected = IntegerField(null=True)
    virustotal_last_modification_date = DateTimeField(null=True)
    timestamp_added = DateTimeField(auto_now_add=True, null=True)
    src_latitude = FloatField(null=True)
    src_longitude = FloatField(null=True)

    CLASSIFICATION_FIELDS = [
        "ip_address",
        "abuseipdb_confidence_score",
        "abuseipdb_total_reports",
        "abuseipdb_num_distinct_users",
        "abuseipdb_recent_reports_count",
        "abuseipdb_last_reported_at",
        "abuseipdb_country_code",
        "abuseipdb_is_whitelisted",
        "apivoid_risk_score",
        "apivoid_blacklists_engines_count",
        "apivoid_blacklists_detection_rate",
        "apivoid_country_name",
        "risk_recommended_pulsedive",
        "stamp_updated_pulsedive",
        "unknown_pulsedive",
        "none_pulsedive",
        "low_pulsedive",
        "medium_pulsedive",
        "high_pulsedive",
        "critical_pulsedive",
        "virustotal_reputation",
        "virustotal_harmless",
        "virustotal_malicious",
        "virustotal_suspicious",
        "virustotal_undetected",
        "virustotal_last_modification_date",
    ]

    def to_classification_dict(self):
        data = model_to_dict(self, fields=self.CLASSIFICATION_FIELDS)
        data["ip"] = data.pop("ip_address")
        return data

    class Meta:
        db_table = 'analysis'

    def __str__(self):
        return self.ip_address


class Blacklist(Model):
    ip_address = CharField(max_length=45, unique=True)
    country_code = CharField(max_length=3, null=True)
    city = CharField(max_length=255, null=True)
    abuseipdb_confidence_score = IntegerField(null=True)
    abuseipdb_total_reports = FloatField(null=True)
    abuseipdb_num_distinct_users = FloatField(null=True)
    abuseipdb_recent_reports_count = IntegerField(null=True)
    abuseipdb_last_reported_at = DateTimeField(null=True, blank=True)
    abuseipdb_country_code = CharField(max_length=3, null=True)
    abuseipdb_is_whitelisted = FloatField(null=True)
    apivoid_risk_score = IntegerField(null=True)
    apivoid_blacklists_engines_count = IntegerField(null=True)
    apivoid_blacklists_detection_rate = FloatField(null=True)
    apivoid_country_name = CharField(null=True)
    risk_recommended_pulsedive = CharField(max_length=45, null=True)
    stamp_updated_pulsedive = DateTimeField(null=True)
    unknown_pulsedive = IntegerField(null=True)
    none_pulsedive = IntegerField(null=True)
    low_pulsedive = IntegerField(null=True)
    medium_pulsedive = IntegerField(null=True)
    high_pulsedive = IntegerField(null=True)
    critical_pulsedive = IntegerField(null=True)
    virustotal_reputation = IntegerField(null=True)
    virustotal_harmless= IntegerField(null=True)
    virustotal_malicious = IntegerField(null=True)
    virustotal_suspicious = IntegerField(null=True)
    virustotal_undetected = IntegerField(null=True)
    virustotal_last_modification_date = DateTimeField(null=True)
    timestamp_added = DateTimeField(auto_now_add=True, null=True)
    src_latitude = FloatField(null=True)
    src_longitude = FloatField(null=True)

    class Meta:
        db_table = 'denylist'

    def __str__(self):
        return self.ip_address
    
class Suspect(Model):
    ip_address = CharField(max_length=45, unique=True)
    country_code = CharField(max_length=3, null=True)
    city = CharField(max_length=255, null=True)
    abuseipdb_confidence_score = IntegerField(null=True)
    abuseipdb_total_reports = FloatField(null=True)
    abuseipdb_num_distinct_users = FloatField(null=True)
    abuseipdb_recent_reports_count = IntegerField(null=True)
    abuseipdb_last_reported_at = DateTimeField(null=True, blank=True)
    abuseipdb_country_code = CharField(max_length=3, null=True)
    abuseipdb_is_whitelisted = FloatField(null=True)
    apivoid_risk_score = IntegerField(null=True)
    apivoid_blacklists_engines_count = IntegerField(null=True)
    apivoid_blacklists_detection_rate = FloatField(null=True)
    apivoid_country_name = CharField(null=True)
    risk_recommended_pulsedive = CharField(max_length=45, null=True)
    stamp_updated_pulsedive = DateTimeField(null=True)
    unknown_pulsedive = IntegerField(null=True)
    none_pulsedive = IntegerField(null=True)
    low_pulsedive = IntegerField(null=True)
    medium_pulsedive = IntegerField(null=True)
    high_pulsedive = IntegerField(null=True)
    critical_pulsedive = IntegerField(null=True)
    virustotal_reputation = IntegerField(null=True)
    virustotal_harmless= IntegerField(null=True)
    virustotal_malicious = IntegerField(null=True)
    virustotal_suspicious = IntegerField(null=True)
    virustotal_undetected = IntegerField(null=True)
    virustotal_last_modification_date = DateTimeField(null=True)
    timestamp_added = DateTimeField(auto_now_add=True, null=True)
    src_latitude = FloatField(null=True)
    src_longitude = FloatField(null=True)

    class Meta:
        db_table = 'suspicious'

    def __str__(self):
        return self.ip_address

