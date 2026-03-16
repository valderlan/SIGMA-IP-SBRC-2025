from rest_framework.serializers import ModelSerializer
from apps.netcontrol.models import Blacklist, Analysis, Whitelist, Suspect

class BlacklistSerializer(ModelSerializer):
    class Meta:
        model = Blacklist
        fields = '__all__'


class WhitelistSerializer(ModelSerializer):
    class Meta:
        model = Whitelist
        fields = '__all__'


class AnalysisSerializer(ModelSerializer):
    class Meta:
        model = Analysis
        fields = '__all__'
        

class SuspectSerializer(ModelSerializer):
    class Meta:
        model = Suspect
        fields = '__all__'