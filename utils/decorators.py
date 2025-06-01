import base64
from datetime import datetime
from functools import wraps
from rest_framework.exceptions import PermissionDenied
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.exceptions import InvalidToken

from users.models import ApiKey
from utils.constants import ACTIVE
from utils.custom_encrypted_field import EncryptionHelper

def secret_key_required(view_func):
    @wraps(view_func)
    def _wrapped_view(request, *args, **kwargs):
        try:
            auth_header = request.headers.get('Authorization')

            if auth_header and auth_header.startswith('Basic '):
                # Extract the base64-encoded credentials part
                encoded_credentials = auth_header.split(' ')[1]

                # Decode the base64-encoded credentials
                decoded_credentials = base64.b64decode(encoded_credentials).decode('utf-8')

                # Split the decoded credentials into username and password
                public_key, secret_key = decoded_credentials.split(':', 1)
                api_key = ApiKey.objects.get(public_key=public_key)
                if secret_key != EncryptionHelper.decrypt_data(api_key.secret_key):
                    raise PermissionDenied('Invalid API Credentials')
                if api_key.has_expired:
                    raise PermissionDenied('API Key has expired')
                if not api_key.user.is_verified:
                    raise PermissionDenied('Client Not Verified')
                if api_key.user.status != ACTIVE:
                    raise PermissionDenied('Client Not Active')
                if not api_key.is_active:
                    raise PermissionDenied('API Key inactive')
                api_key.last_used = datetime.now()
                api_key.save()
                request.user = api_key.user
                return view_func(request, *args, **kwargs)
            else:
                raise PermissionDenied("Invalid Authorization Format")
        except ApiKey.DoesNotExist as e:
            raise PermissionDenied(str(e))
    return _wrapped_view


def jwt_login_required(view_func):
    @wraps(view_func)
    def _wrapped_view(request, *args, **kwargs):
        try:
            header = request.headers.get('Authorization')
            if not header or not header.startswith('JWT '):
                raise InvalidToken('No valid JWT token provided in Authorization header.')

            token = header.split()[1]
            jwt_authentication = JWTAuthentication()
            validated_token = jwt_authentication.get_validated_token(token)
            user = jwt_authentication.get_user(validated_token)
            request.user = user

            return view_func(request, *args, **kwargs)
        except InvalidToken as e:
            raise PermissionDenied(str(e))
    return _wrapped_view
