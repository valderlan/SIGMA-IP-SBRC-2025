import django_filters
from rest_framework import filters
from netcontrol.models import Blacklist, Whitelist, Tarpit


class BlacklistFilter(django_filters.FilterSet):
    class Meta:
        model = Blacklist
        fields = {
            'ip_address': ['exact', 'icontains'],
            'country_code': ['exact'],
            'city': ['exact', 'icontains'],
            'abuse_confidence_score': ['exact', 'gte', 'lte'],
            'last_reported_at': ['exact', 'date__gte', 'date__lte'],
            'timestamp_added': ['exact', 'date__gte', 'date__lte'],
        }


class WhitelistFilter(django_filters.FilterSet):
    class Meta:
        model = Whitelist
        fields = {
            'ip_address': ['exact', 'icontains'],
            'timestamp_added': ['exact', 'date__gte', 'date__lte'],
        }


class TarpitFilter(django_filters.FilterSet):
    class Meta:
        model = Tarpit
        fields = {
            'ip_address': ['exact', 'icontains'],
            'country_code': ['exact'],
            'abuse_confidence_score': ['exact', 'gte', 'lte'],
            'last_reported_at': ['exact', 'date__gte', 'date__lte'],
            'src_latitude': ['exact', 'gte', 'lte'],
            'src_longitude': ['exact', 'gte', 'lte'],
        }

