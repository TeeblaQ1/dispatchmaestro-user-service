from datetime import datetime, timedelta
import uuid
from django.db import models
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin, UserManager
from django.utils import timezone
from rest_framework_simplejwt.tokens import RefreshToken

from utils.classes.base_model import BaseModel
from utils.classes.managers import ActiveObjectsManager, NonDeletedObjectsManager
from utils.constants import ACTIVE, CLIENT, DELETED, INACTIVE, LIVE, PARTNER, TEST, ENTITY_TYPES, STATUS_TYPES
from utils.custom_encrypted_field import EncryptedField
from utils.keygen import generate_apikeys, generate_public_key

# Create your models here.
class User(AbstractBaseUser, PermissionsMixin):

    ENTITY_CHOICES = (
        (CLIENT, CLIENT), (PARTNER, PARTNER)
    )

    STATUS_CHOICES = (
        (ACTIVE, ACTIVE), (INACTIVE, INACTIVE), (DELETED, DELETED)
    )

    ENV_CHOICES = (
        (TEST, TEST), (LIVE, LIVE)
    )
    
    email = models.EmailField(max_length=255, unique=True, db_index=True)
    is_verified = models.BooleanField(default=False)

    status = models.CharField(max_length=10, choices=STATUS_TYPES, default=ACTIVE)
    environment = models.CharField(max_length=10, default="test")
    
    entity_id = models.UUIDField()
    entity_type = models.CharField(max_length=10, choices=ENTITY_TYPES)

    meta = models.JSONField(default=dict)
    date_created = models.DateTimeField(auto_now_add=True)
    last_updated = models.DateTimeField(auto_now=True)

    USERNAME_FIELD = "email"

    objects = UserManager()

    def __str__(self):
        return self.email
    
    def tokens(self):
        refresh = RefreshToken.for_user(self)
        return {
            'refresh': str(refresh),
            'access_token': str(refresh.access_token)
        }

User.groups.field.remote_field.related_name = 'user_groups'
User.user_permissions.field.remote_field.related_name = 'user_user_permissions'


class ApiKey(BaseModel):

    STATUS_CHOICES = (
        (ACTIVE, ACTIVE), (INACTIVE, INACTIVE), (DELETED, DELETED)
    )

    user = models.ForeignKey(User, null=True, blank=True, on_delete=models.CASCADE, related_name="apikeys")
    status = models.CharField(max_length=10, choices=STATUS_TYPES, default=ACTIVE)
    max_request = models.PositiveIntegerField(null=True, blank=True)
    public_key = models.CharField(max_length=32, null=True, unique=True)
    secret_key = EncryptedField(null=True)
    expires_at = models.DateTimeField(null=True)
    last_used = models.DateTimeField(auto_now=True, null=True)

    active = ActiveObjectsManager()
    objects = NonDeletedObjectsManager()
    all_objects = models.Manager()

    @property
    def has_expired(self):
        return timezone.now() > self.expires_at
    
    @property
    def is_active(self):
        return self.status == ACTIVE

    def save(self, *args, **kwargs):
        if not self.public_key:
            self.public_key = generate_public_key()
        if not self.secret_key:
            self.secret_key = generate_apikeys()
        if not self.expires_at:
            self.expires_at = datetime.now() + timedelta(days=365)
        super(ApiKey, self).save(*args, **kwargs)


class ClientInfo(models.Model):
    id = models.UUIDField(primary_key=True)
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='client_info')
    first_name = models.CharField(max_length=255)
    last_name = models.CharField(max_length=255)
    email_address = models.EmailField()
    phone_number = models.CharField(max_length=20)
    description = models.TextField(null=True, blank=True)
    website_url = models.URLField(null=True, blank=True)
    role = models.CharField(max_length=50)
    status = models.CharField(max_length=10, choices=STATUS_TYPES, default=ACTIVE)
    country = models.CharField(max_length=100)
    business_name = models.CharField(max_length=255)
    logo = models.URLField(null=True, blank=True)
    meta = models.JSONField(default=dict, blank=True)
    date_created = models.DateTimeField(auto_now_add=True)
    last_updated = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "client_info"


class PartnerInfo(models.Model):
    id = models.UUIDField(primary_key=True)
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='partner_info')
    name = models.CharField(max_length=255)
    email_address = models.EmailField()
    phone_number = models.CharField(max_length=20)
    description = models.TextField(null=True, blank=True)
    website_url = models.URLField(null=True, blank=True)
    status = models.CharField(max_length=10, choices=STATUS_TYPES, default=ACTIVE)
    country = models.CharField(max_length=100)
    logo = models.URLField(null=True, blank=True)
    meta = models.JSONField(default=dict, blank=True)
    date_created = models.DateTimeField(auto_now_add=True)
    last_updated = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "partner_info"
