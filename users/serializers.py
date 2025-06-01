from requests.exceptions import HTTPError
from rest_framework import serializers
from rest_framework.exceptions import NotFound
from rest_framework_simplejwt.serializers import TokenVerifySerializer

from services.core import DispatchMaestro
from utils.constants import CLIENT
from .models import ApiKey, User, ClientInfo, PartnerInfo
from config.settings import SECRET_KEY, cipher_suite


class UserSerializer(serializers.ModelSerializer):

    class Meta:
        model = User
        fields = ("entity_id", "entity_type", "environment", "status", "is_verified")


class ApiKeySerializer(serializers.ModelSerializer):

    secret_key = serializers.SerializerMethodField()

    class Meta:
        model = ApiKey
        fields = "__all__"
    
    def get_secret_key(self, obj):
        return cipher_suite.decrypt(obj.secret_key.encode()).decode()


class ClientInfoSerializer(serializers.ModelSerializer):
    class Meta:
        model = ClientInfo
        exclude = ('user',)


class PartnerInfoSerializer(serializers.ModelSerializer):
    class Meta:
        model = PartnerInfo
        exclude = ('user',)


class CustomTokenVerifySerializer(TokenVerifySerializer):
    token = serializers.CharField()

    def validate(self, attrs):
        import jwt
        super().validate(attrs)
        payload = jwt.decode(attrs["token"], SECRET_KEY, algorithms=["HS256"])
        user = User.objects.get(id=payload["user_id"])
        
        try:
            if user.entity_type == CLIENT:
                client_info = user.client_info
                if not client_info:
                    raise NotFound("Client information not found")
                response = {**ClientInfoSerializer(client_info).data, "environment": user.environment}
            else:
                partner_info = user.partner_info
                if not partner_info:
                    raise NotFound("Partner information not found")
                response = PartnerInfoSerializer(partner_info).data
            return response
        except (ClientInfo.DoesNotExist, PartnerInfo.DoesNotExist):
            raise NotFound("Entity information not found")
