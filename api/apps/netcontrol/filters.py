from django_filters import FilterSet, CharFilter, NumberFilter, DateTimeFilter
from apps.netcontrol.models import Blacklist, Whitelist, Tarpit, Suspect


class BlacklistFilter(FilterSet):
    ip_address = CharFilter(field_name="ip_address", lookup_expr="iexact")
    country_code = CharFilter(field_name="country_code", lookup_expr="iexact")
    city = CharFilter(field_name="city", lookup_expr="iexact")
    abuseipdb_confidence_score__gte = NumberFilter(field_name="abuseipdb_confidence_score", lookup_expr="gte")
    abuseipdb_confidence_score__lte = NumberFilter(field_name="abuseipdb_confidence_score", lookup_expr="lte")
    last_reported_at__gte = DateTimeFilter(
        field_name="last_reported_at", lookup_expr="gte"
    )
    last_reported_at__lte = DateTimeFilter(
        field_name="last_reported_at", lookup_expr="lte"
    )
    timestamp_added__gte = DateTimeFilter(
        field_name="timestamp_added", lookup_expr="gte"
    )
    timestamp_added__lte = DateTimeFilter(
        field_name="timestamp_added", lookup_expr="lte"
    )

    class Meta:
        model = Blacklist
        fields = [
            "ip_address",
            "country_code",
            "city",
            "abuseipdb_confidence_score",
            "last_reported_at",
            "timestamp_added",
        ]


class WhitelistFilter(FilterSet):
    ip_address = CharFilter(field_name="ip_address", lookup_expr="iexact")
    country_code = CharFilter(field_name="country_code", lookup_expr="iexact")
    city = CharFilter(field_name="city", lookup_expr="iexact")
    abuseipdb_confidence_score__gte = NumberFilter(field_name="abuseipdb_confidence_score", lookup_expr="gte")
    abuseipdb_confidence_score__lte = NumberFilter(field_name="abuseipdb_confidence_score", lookup_expr="lte")
    last_reported_at__gte = DateTimeFilter(
        field_name="last_reported_at", lookup_expr="gte"
    )
    last_reported_at__lte = DateTimeFilter(
        field_name="last_reported_at", lookup_expr="lte"
    )
    timestamp_added__gte = DateTimeFilter(
        field_name="timestamp_added", lookup_expr="gte"
    )
    timestamp_added__lte = DateTimeFilter(
        field_name="timestamp_added", lookup_expr="lte"
    )

    class Meta:
        model = Whitelist
        fields = [
            "ip_address",
            "country_code",
            "city",
            "abuseipdb_confidence_score",
            "last_reported_at",
            "timestamp_added",
        ]


class TarpitFilter(FilterSet):
    ip_address = CharFilter(field_name="ip_address", lookup_expr="iexact")
    country_code = CharFilter(field_name="country_code", lookup_expr="iexact")
    city = CharFilter(field_name="city", lookup_expr="iexact")
    abuseipdb_confidence_score__gte = NumberFilter(field_name="abuseipdb_confidence_score", lookup_expr="gte")
    abuseipdb_confidence_score__lte = NumberFilter(field_name="abuseipdb_confidence_score", lookup_expr="lte")
    last_reported_at__gte = DateTimeFilter(
        field_name="last_reported_at", lookup_expr="gte"
    )
    last_reported_at__lte = DateTimeFilter(
        field_name="last_reported_at", lookup_expr="lte"
    )
    timestamp_added__gte = DateTimeFilter(
        field_name="timestamp_added", lookup_expr="gte"
    )
    timestamp_added__lte = DateTimeFilter(
        field_name="timestamp_added", lookup_expr="lte"
    )

    class Meta:
        model = Tarpit
        fields = [
            "ip_address",
            "country_code",
            "city",
            "abuseipdb_confidence_score",
            "last_reported_at",
            "timestamp_added",
        ]


class SuspectFilter(FilterSet):
    ip_address = CharFilter(field_name="ip_address", lookup_expr="iexact")
    country_code = CharFilter(field_name="country_code", lookup_expr="iexact")
    city = CharFilter(field_name="city", lookup_expr="iexact")
    abuseipdb_confidence_score__gte = NumberFilter(field_name="abuseipdb_confidence_score", lookup_expr="gte")
    abuseipdb_confidence_score__lte = NumberFilter(field_name="abuseipdb_confidence_score", lookup_expr="lte")
    last_reported_at__gte = DateTimeFilter(
        field_name="last_reported_at", lookup_expr="gte"
    )
    last_reported_at__lte = DateTimeFilter(
        field_name="last_reported_at", lookup_expr="lte"
    )
    timestamp_added__gte = DateTimeFilter(
        field_name="timestamp_added", lookup_expr="gte"
    )
    timestamp_added__lte = DateTimeFilter(
        field_name="timestamp_added", lookup_expr="lte"
    )

    class Meta:
        model = Suspect
        fields = [
            "ip_address",
            "country_code",
            "city",
            "abuseipdb_confidence_score",
            "last_reported_at",
            "timestamp_added",
        ]
