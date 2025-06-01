from django.core.mail import EmailMessage
from django.core.paginator import Paginator
import string
import random
from rest_framework_simplejwt.tokens import RefreshToken

from config.settings import FRONTEND_URL
from users.models import User

class Util:
    @staticmethod
    def send_email(email_data):
        email = EmailMessage(
            subject=email_data['email_subject'],
            body=email_data['email_body'],
            to=email_data['to_email'],
        )
        email.send()
    
    @staticmethod   
    def send_verification_mail(first_name, user: User):
        token = RefreshToken.for_user(user).access_token
        absurl = FRONTEND_URL + "/auth/verify?token=" + str(token)
        email_body = "Hello " + first_name + ", \n\n Use this link to verify your email: \n" + absurl
        email_data = {'email_body': email_body, 'to_email': [user.email], 'email_subject': 'Email Verification'}
        Util.send_email(email_data)

    @staticmethod
    def pagination_query(query_set, page_count, page_number):
        """
        Breaks down retrieved records into chunks per page
        :param query_set: Query Set to be paginated
        :param page_count: Number of records in each page.
        :param page_number: The actual page
        :returns a tuple of the paginated record,
        number of pages and the total number of items
        """
        paginator = Paginator(query_set, page_count)
        return paginator.get_page(page_number), paginator.num_pages, len(query_set)

    def get_alphabet_position(letter):
        # Convert the letter to uppercase to handle both uppercase and lowercase inputs
        uppercase_letter = str(letter).upper()

        # Get the index (position) of the letter in the alphabet
        alphabet = string.ascii_uppercase
        position = alphabet.find(uppercase_letter) + 1  # Add 1 because indexing starts from 0

        if position > 0:
            return position
        else:
            return None

    @staticmethod
    def get_alphabet_from_position(position):
        # Ensure the position is within the valid range (1 to 26)
        if 1 <= position <= 26:
            # Get the alphabet string
            alphabet = string.ascii_uppercase
            # Get the letter at the specified position
            letter = alphabet[position - 1]  # Subtract 1 because indexing starts from 0
            return letter
        else:
            return None  # Invalid position
        
    @staticmethod
    def get_truncated_id(id_str: str):
        """id_str must be in this format fa3ab8f5-b84e-45f1-af53-c80208aa896e"""
        return id_str.split("-")[0]
    
    @staticmethod
    def generate_otp(length=6):
        """Generate a random OTP of the specified length."""
        otp = ''.join(random.choice('0123456789') for _ in range(length))
        return otp
    
    @staticmethod
    def format_otp(otp: str):
        if isinstance(otp, str):
            return " ".join(otp)
        else:
            ""

class KwargsUtil:
    @classmethod
    def cherry_pick(cls, kwargs: dict, items: list) -> list:
        return [kwargs.get(item) or None for item in items]
