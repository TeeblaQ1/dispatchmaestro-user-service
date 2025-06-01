from rest_framework_simplejwt.tokens import RefreshToken
from config.settings import FRONTEND_URL
from utils.classes.utils import Util


class UsersUtil:

    @staticmethod
    def send_verification_mail(user, entity_info):
        token = RefreshToken.for_user(user).access_token
        absurl = FRONTEND_URL + "/auth/verify?token=" + str(token)
        email_body = "Hello " + entity_info["first_name"] + ", \n\n Use this link to verify your email: \n" + absurl
        email_data = {'email_body': email_body, 'to_email': [entity_info["email"]], 'email_subject': 'Email Verification'}
        Util.send_email(email_data)
