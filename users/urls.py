from django.urls import path
from rest_framework_simplejwt.views import TokenRefreshView
from users import views

urlpatterns = [
    path("", views.UsersViewset.as_view({
        "post": "create_user",
        "get": "get_user_info",
        "put": "edit_user"
    })),
    path("login", views.UsersViewset.as_view({
        "post": "login_user"
    })),
    path("change-password", views.UsersViewset.as_view({
        "put": "change_password"
    })),
    path("api-keys", views.UsersViewset.as_view({
        "get": "get_api_keys",
        "post": "generate_api_keys"
    })),
    path("via-keys", views.UsersViewset.as_view({
        "get": "get_user_info_via_keys",
    })),
    path("switch-environment", views.UsersViewset.as_view({
        "post": "switch_environment"
    })),
    path("logout", views.UsersViewset.as_view({
        "post": "logout"
    })),
    path("reset-password", views.UsersViewset.as_view({
        "post": "reset_password" 
    })),
    path("reset-password/confirm/<uidb64>/<token>", views.UsersViewset.as_view({
        "patch": "reset_password_confirm"
    }), name="reset_password_confirm"),
    path("verify-email", views.UsersViewset.as_view({
        "post": "verify_email", 
    })),
    path("verify-email/confirm/<token>", views.UsersViewset.as_view({
        "patch": "verify_email_confirm", 
    }), name="verify_email_confirm"),
    path("get_secret/<entity_id>", views.UsersViewset.as_view({
        "get": "get_entity_secret"
    })),
    path("webhook", views.entity_info_webhook, name="entity_info_webhook"),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
]
