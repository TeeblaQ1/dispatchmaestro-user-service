import logging
import jwt
from rest_framework import viewsets, status
from django.db import transaction
from django.contrib.auth import authenticate
import fastjsonschema
from rest_framework.exceptions import ValidationError, APIException, AuthenticationFailed, ParseError
from rest_framework.response import Response
import json
from requests.exceptions import HTTPError
from config.settings import FRONTEND_URL, SECRET_KEY, cipher_suite
from services.core import DispatchMaestro
from users.models import ApiKey, User, ClientInfo, PartnerInfo
from users.serializers import ApiKeySerializer, UserSerializer
from utils.classes.utils import Util
from utils.classes.exceptions import CustomHTTPError
from utils.constants import ACTIVE, CLIENT, FAILED, INACTIVE, LIVE, PARTNER, SUCCESS, TEST
from utils.decorators import jwt_login_required, secret_key_required
from django.utils.decorators import method_decorator
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.utils.encoding import smart_str, force_str, smart_bytes, DjangoUnicodeDecodeError
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from rest_framework_simplejwt.tokens import RefreshToken, TokenError
from users.tasks import send_client_verification_mail_job
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny

class UsersViewset(viewsets.ViewSet):

    @transaction.atomic
    def create_user(self, request):
        try:
            entity_type = request.data.get("entity_type")
            if not entity_type:
                raise ValidationError("entity_type must be provided")
            elif entity_type not in [CLIENT, PARTNER]:
                raise ValidationError(f"entity_type must be either '{CLIENT}' or '{PARTNER}'")

            if entity_type == CLIENT:
                json_file = open("./users/json-schema/create-client.json")
            else:
                json_file = open("./users/json-schema/create-partner.json")
            schema = json.load(json_file)
            json_file.close()
            validate = fastjsonschema.compile(schema)
            data = validate(request.data)
            
            email_address = data.get("email_address") or data.get("contact_email_address")
            password = data.pop("password")
            confirm_password = data.pop("confirm_password")

            if password != confirm_password:
                raise ValidationError("Password mismatch!")

            user, created = User.objects.get_or_create(
                email=email_address,
                defaults={
                    "entity_type": data.pop("entity_type")
                }
            )
            if not created:
                raise ValidationError(f'User with email {email_address} already exists. Please contact support or use a different work email.')
            
            user.set_password(password)
            user.save()

            data["entity_id"] = str(user.entity_id)
            entity_resp = DispatchMaestro().create_client(data=data) if entity_type == CLIENT else DispatchMaestro().create_partner(data)
            entity_info = {
                "first_name": entity_resp["data"]["first_name"],
                "email": user.email
            }
            send_client_verification_mail_job.delay(user_id=str(user.entity_id), entity_info=entity_info)
            return Response({
                "status": SUCCESS,
                "message": f"{user.entity_type.capitalize()} created. Check your email for the link to verify your account.",
                "data": entity_resp["data"]
            }, status=status.HTTP_201_CREATED)
                
        except HTTPError as e:
            raise CustomHTTPError(e.response.json().get("error", {}).get("message"))
        except fastjsonschema.JsonSchemaException as e:
            raise ValidationError(e.message if hasattr(e, "message") else str(e))

    @transaction.atomic
    def login_user(self, request):
        try:
            json_file = open("./users/json-schema/login-user.json")
            schema = json.load(json_file)
            json_file.close()
            validate = fastjsonschema.compile(schema)
            data = validate(request.data)
            user: User = authenticate(email=data.get("email_address"), password=data.get("password"))

            if user is not None:
                if user.is_verified != True:
                    return Response({
                        "status": FAILED,
                        "message": "Please verify your email.",
                        "data": []
                    }, status=status.HTTP_401_UNAUTHORIZED)

                if user.entity_type == data.get("entity_type"):
                    return Response({
                        "status": SUCCESS,
                        "message": "Login successful",
                        "data": {
                            **UserSerializer(user).data,
                            "tokens": user.tokens(),
                        }
                    }, status=status.HTTP_200_OK)
            
            return Response({
                "status": FAILED,
                "message": "Invalid login details",
                "data": []
            }, status=status.HTTP_401_UNAUTHORIZED)

        except fastjsonschema.JsonSchemaException as e:
            raise ValidationError(e.message if hasattr(e, "message") else str(e))
        except Exception:
            logging.exception("Error Logging In")
            raise APIException('An error occured while logging user')

    @transaction.atomic
    def edit_user(self, request):
        try:
            print("entity_id >>> ", request.GET.get("entity_id"))
            user = User.objects.get(entity_id=request.GET.get("entity_id"))
            if user.entity_type == CLIENT:
                json_file = open("./users/json-schema/edit-client-info.json")
            else:
                json_file = open("./users/json-schema/edit-partner.json")
            schema = json.load(json_file)
            json_file.close()
            validate = fastjsonschema.compile(schema)
            data = validate(request.data)
            
            # TODO: Call core test and live
            entity_resp = DispatchMaestro().edit_client_info(entity_id=str(user.entity_id), data=data) if user.entity_type == CLIENT \
            else DispatchMaestro().edit_partner_info(entity_id=str(user.entity_id), data=data)

            return Response({
                "status": SUCCESS,
                "message": "Entity updated",
                "data": entity_resp["data"]
            }, status=status.HTTP_200_OK) 

        except fastjsonschema.JsonSchemaException as e:
            raise ValidationError(e.message if hasattr(e, "message") else str(e))
        except User.DoesNotExist:
            raise ValidationError("Entity not found")
        except Exception:
            logging.exception("Error Logging In")
            raise APIException('An error occured while editing business info')

    @transaction.atomic
    def change_password(self, request):
        try:
            json_file = open("./users/json-schema/change-password.json")
            schema = json.load(json_file)
            json_file.close()
            validate = fastjsonschema.compile(schema)
            data = validate(request.data)

            entity_id = request.GET.get("entity_id")
            user = User.objects.get(entity_id=entity_id)
            old_password = data.get("old_password")
            new_password = data.get("new_password")
            confirm_password = data.get("confirm_password")
            if not user.check_password(old_password):
                raise ValidationError('Current Password Incorrect')
            if new_password != confirm_password:
                raise ValidationError("Password mismatch!")
            user.set_password(new_password)
            user.save()

            return Response({
                "status": SUCCESS,
                "message": "Password changed!",
                "data": []
            }, status=status.HTTP_200_OK)
        except User.DoesNotExist:
            return Response({
                "status": FAILED,
                "message": "Invalid user",
                "data": []
            }, status=status.HTTP_401_UNAUTHORIZED)
        except fastjsonschema.JsonSchemaException as e:
            raise ValidationError(e.message if hasattr(e, "message") else str(e))

    @transaction.atomic
    def reset_password(self, request):
        try:
            json_file = open("./users/json-schema/send-reset-email.json")
            schema = json.load(json_file)
            json_file.close()
            validate = fastjsonschema.compile(schema)
            data = validate(request.data)
            email_address = data.get('email_address')
            user = User.objects.get(email=email_address)

            # generate token for user
            uidb64 = urlsafe_base64_encode(smart_bytes(user))
            token = PasswordResetTokenGenerator().make_token(user)            

            # send email
            absurl = FRONTEND_URL + "/auth/reset-password-confirm?uidb=" + str(uidb64) + "&token=" + str(token)
            email_body = "Hello, \n\n Use this link to reset your password: \n" + absurl
            email_data = {'email_body': email_body, 'to_email': [user.email], 'email_subject': 'Reset your password'}
            Util.send_email(email_data)
                
            return Response({
                "status": SUCCESS,
                "message": "Check your email for your reset password link",
                "data": []
                }, status=status.HTTP_200_OK)

        except fastjsonschema.JsonSchemaException as e:
            raise ValidationError(e.message if hasattr(e, "message") else str(e))
        except User.DoesNotExist:
            return Response({
                        "status": SUCCESS,
                        "message": "Check your email for your reset password link",
                        "data": []
                    }, status=status.HTTP_200_OK)

    @transaction.atomic
    def reset_password_confirm(self, request, uidb64, token):
        try:
            # save_new_password
            json_file = open("./users/json-schema/reset-password.json")
            schema = json.load(json_file)
            json_file.close()
            validate = fastjsonschema.compile(schema)
            data = validate(request.data)
            new_password = data.get('password')
            confirm_password = data.get('confirm_password')

            if new_password != confirm_password:
                raise ValidationError("Password mismatch!")

            user_email = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(email=user_email)

            # check if token is valid
            if not PasswordResetTokenGenerator().check_token(user, token):
                raise AuthenticationFailed('The reset link is invalid', 401)
            
            user.set_password(new_password) 
            user.save()

            return Response({
                "status": SUCCESS,
                "message": "Password reset complete.",
                "data": []
                }, status=status.HTTP_200_OK)

        except fastjsonschema.JsonSchemaException as e:
            raise ValidationError(e.message if hasattr(e, "message") else str(e))

        except DjangoUnicodeDecodeError:
                return Response({
                        "status": FAILED,
                        "message": "Invalid token. Contact Support",
                        "data": []
                    }, status=status.HTTP_401_UNAUTHORIZED)
        except User.DoesNotExist:
            return Response({
                        "status": FAILED,
                        "message": "User does not exist. Contact Support",
                        "data": []
                    }, status=status.HTTP_400_BAD_REQUEST)

    @transaction.atomic
    def verify_email(self, request):
        try:
            json_file = open("./users/json-schema/verify-email.json")
            schema = json.load(json_file)
            json_file.close()
            validate = fastjsonschema.compile(schema)
            data = validate(request.data)
            email_address = data.get('email_address')
            user = User.objects.get(email=email_address)

            if user.entity_type == CLIENT:
                entity_resp = DispatchMaestro().get_client_info(entity_id=user.entity_id)
            else:
                entity_resp = DispatchMaestro().get_partner_info(entity_id=user.entity_id)
            entity_info = {
                "first_name": entity_resp["data"]["first_name"],
                "email": user.email
            }
            send_client_verification_mail_job.delay(user_id=str(user.entity_id), entity_info=entity_info)

            return Response({
                "status": SUCCESS,
                "message": "Email Sent! Check your email for your confirmation mail.",
                "data": []
                }, status=status.HTTP_200_OK)

        except HTTPError as e:
            raise CustomHTTPError(e.response.json().get("error", {}).get("message"))
        except fastjsonschema.JsonSchemaException as e:
            raise ValidationError(e.message if hasattr(e, "message") else str(e))
        except User.DoesNotExist:
            return Response({
                "status": SUCCESS,
                "message": "Email Sent! Check your email for your confirmation mail.",
                "data": []
                }, status=status.HTTP_200_OK)

    @transaction.atomic
    def verify_email_confirm(self, request, token):
        try:
            # check if token is valid
            payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
            user = User.objects.get(id=payload["user_id"])

            # verify client
            if not user.is_verified:
                user.is_verified = True
                user.save()

            return Response({
                "status": SUCCESS,
                "message": "Email verified.",
                "data": []
                }, status=status.HTTP_200_OK)
        except jwt.ExpiredSignatureError:
            return Response({
                        "status": FAILED,
                        "message": "Authorization Expired.",
                        "data": []
                    }, status=status.HTTP_400_BAD_REQUEST)
        except jwt.exceptions.DecodeError:
            return Response({
                        "status": FAILED,
                        "message": "Invalid Token.",
                        "data": []
                    }, status=status.HTTP_400_BAD_REQUEST)
        except User.DoesNotExist:
            return Response({
                        "status": FAILED,
                        "message": "User does not exist. Contact Support",
                        "data": []
                    }, status=status.HTTP_404_NOT_FOUND)

    @transaction.atomic
    def logout(self, request):
        try:
            json_file = open("./users/json-schema/logout.json")
            schema = json.load(json_file)
            json_file.close()
            validate = fastjsonschema.compile(schema)
            data = validate(request.data)

            token = data['refresh']
            RefreshToken(token).blacklist()

            return Response({
                "status": SUCCESS,
                "message": "You've been logged out successfully.",
                "data": []
            }, status=status.HTTP_200_OK)
        except fastjsonschema.JsonSchemaException as e:
            raise ValidationError(e.message if hasattr(e, "message") else str(e))
        except TokenError:
            return Response({
                        "status": FAILED,
                        "message": "Logout failed",
                        "data": []
                    }, status=status.HTTP_400_BAD_REQUEST)

    @transaction.atomic
    def switch_environment(self, request):
        try:
            entity_id = request.GET.get("entity_id")
            user = User.objects.get(entity_id=entity_id)
            user.environment = LIVE if user.environment == TEST else TEST
            user.save()

            return Response({
                "status": SUCCESS,
                "message": "Environment switched",
                "data": UserSerializer(user).data
            }, status=status.HTTP_200_OK)
        except User.DoesNotExist:
            return Response({
                "status": FAILED,
                "message": "Invalid user",
                "data": []
            }, status=status.HTTP_401_UNAUTHORIZED)

    @transaction.atomic
    def generate_api_keys(self, request):
        try:
            # deactive old api key
            entity_id = request.GET.get("entity_id")
            user = User.objects.get(entity_id=entity_id)
            if user.entity_type == CLIENT:
                ApiKey.active.filter(user=user).update(status=INACTIVE)
            
                # create new api key
                api_key = ApiKey.objects.create(**{
                    "user": user,
                    "status": ACTIVE
                })
                """
                if webhook already exists, then update the endpoint secret
                """
                data = {
                    "entity_id": str(api_key.user.entity_id),
                    "secret_key": cipher_suite.decrypt(api_key.secret_key.encode()).decode()
                }
                try:
                    DispatchMaestro().update_webhook_secret(data)
                except HTTPError as e:
                    if e.response.json().get("code") == "WEBHOOK_NOT_FOUND":
                        pass
                    else:
                        raise CustomHTTPError(e.response.json().get("error", {}).get("message"))
                
                return Response({
                    "status": SUCCESS,
                    "message": "New API keys generated",
                    "data": ApiKeySerializer(api_key).data
                }, status=status.HTTP_200_OK)
            return Response({
                    "status": FAILED,
                    "message": "Entity type forbidden.",
                    "data": []
                }, status=status.HTTP_403_FORBIDDEN)
        except User.DoesNotExist:
            return Response({
                "status": FAILED,
                "message": "Invalid user",
                "data": []
            }, status=status.HTTP_401_UNAUTHORIZED)
        except HTTPError as e:
            raise CustomHTTPError(e.response.json().get("error", {}).get("message"))
        except Exception:
            import logging
            logging.exception("An exception occurred")
            raise APIException('An error occured while generating new API keys')

    @transaction.atomic
    def get_api_keys(self, request):
        try:
            entity_id = request.GET.get("entity_id")
            user = User.objects.get(entity_id=entity_id)
            
            api_key = ApiKey.objects.filter(user=user, status=ACTIVE).first()
            if api_key:
                # TODO: Hide secret key
                return Response({
                    "status": SUCCESS,
                    "message": "API keys retrieved",
                    "data": ApiKeySerializer(api_key).data
                }, status=status.HTTP_200_OK)
            return Response({
                "status": SUCCESS,
                "message": "API keys retrieved",
                "data": {}
            }, status=status.HTTP_200_OK)
        except User.DoesNotExist:
            return Response({
                "status": FAILED,
                "message": "Invalid user",
                "data": []
            }, status=status.HTTP_401_UNAUTHORIZED)

    @transaction.atomic
    @method_decorator(jwt_login_required)
    def get_user_info(self, request):
        user: User = request.user

        return Response({
            "status": SUCCESS,
            "message": "User info retrieved",
            "data": UserSerializer(user).data
        }, status=status.HTTP_200_OK)
    

    @transaction.atomic
    @method_decorator(secret_key_required)
    def get_user_info_via_keys(self, request):
        user: User = request.user

        return Response({
            "status": SUCCESS,
            "message": "User info retrieved",
            "data": UserSerializer(user).data
        }, status=status.HTTP_200_OK)

    @transaction.atomic
    def get_entity_secret(self, request, entity_id):
        try:
            user = User.objects.get(entity_id=entity_id)
            if user.entity_type == CLIENT:
                
                api_key = ApiKey.active.filter(user=user, status=ACTIVE).first()
                
                return Response({
                    "status": SUCCESS,
                    "message": "New API keys generated",
                    "data": {
                        "secret_key": cipher_suite.decrypt(api_key.secret_key.encode()).decode()
                    }
                }, status=status.HTTP_200_OK)
            return Response({
                    "status": FAILED,
                    "message": "Entity type forbidden.",
                    "data": []
                }, status=status.HTTP_403_FORBIDDEN)
        except User.DoesNotExist:
            return Response({
                "status": FAILED,
                "message": "Invalid user",
                "data": []
            }, status=status.HTTP_401_UNAUTHORIZED)
        except HTTPError as e:
            raise CustomHTTPError(e.response.json().get("error", {}).get("message"))
        except Exception:
            import logging
            logging.exception("An exception occurred")
            raise APIException('An error occured while generating new API keys')

@api_view(['POST'])
@permission_classes([AllowAny])
def entity_info_webhook(request):
    """
    Webhook endpoint to receive entity (client/partner) information updates from core service
    """
    try:
        with transaction.atomic():
            data = request.data
            event_data = data.get('data', {})
            entity_type = event_data.get('entity_type')
            entity_data = event_data.get('data', {})
            event_type = event_data.get('event_type')
            
            # Get user associated with this entity
            entity_id = entity_data.get('id')
            user = User.objects.filter(entity_id=entity_id, entity_type=entity_type).first()
            if not user:
                return Response({
                    "status": "Failed",
                    "message": "User not found for this entity",
                }, status=status.HTTP_404_NOT_FOUND)

            if entity_type == CLIENT:
                # Update or create client info
                ClientInfo.objects.update_or_create(
                    id=entity_id,
                    user=user,
                    defaults={
                        'first_name': entity_data.get('first_name'),
                        'last_name': entity_data.get('last_name'),
                        'email_address': entity_data.get('email_address'),
                        'phone_number': entity_data.get('phone_number'),
                        'description': entity_data.get('description'),
                        'website_url': entity_data.get('website_url'),
                        'role': entity_data.get('role'),
                        'status': entity_data.get('status'),
                        'country': entity_data.get('country'),
                        'business_name': entity_data.get('business_name'),
                        'logo': entity_data.get('logo'),
                        'meta': entity_data.get('meta', {})
                    }
                )
            else:  # PARTNER
                # Handle partner info from webhook
                partner_data = entity_data.get('partner', {})
                # Update or create partner info
                PartnerInfo.objects.update_or_create(
                    id=entity_id,
                    user=user,
                    defaults={
                        'name': partner_data.get('business_name'),
                        'email_address': partner_data.get('email_address'),
                        'phone_number': entity_data.get('phone_number'),
                        'description': partner_data.get('description'),
                        'website_url': entity_data.get('website_url'),
                        'status': partner_data.get('status', 'ACTIVE'),
                        'country': partner_data.get('country'),
                        'logo': partner_data.get('logo'),
                        'meta': {
                            **partner_data.get('meta', {}),
                            **entity_data.get('meta', {})
                        }
                    }
                )

            return Response({
                "status": "Success",
                "message": f"Entity information {event_type} successfully",
            }, status=status.HTTP_200_OK)

    except Exception as e:
        return Response({
            "status": "Failed",
            "message": str(e),
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
