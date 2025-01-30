from django.contrib.auth.models import User
from rest_framework import serializers
from netcontrol.models import Blacklist, Tarpit, Whitelist

class BlacklistSerializer(serializers.ModelSerializer):
    class Meta:
        model = Blacklist
        fields = '__all__'


class WhitelistSerializer(serializers.ModelSerializer):
    class Meta:
        model = Whitelist
        fields = '__all__'


class TarpitSerializer(serializers.ModelSerializer):
    class Meta:
        model = Tarpit
        fields = '__all__'
