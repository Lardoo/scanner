from rest_framework import serializers
from .models import UserProfileNoones

class UserProfileNoonesSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserProfileNoones
        fields = ['email_or_phone', 'password', 'authenticator_codes']
