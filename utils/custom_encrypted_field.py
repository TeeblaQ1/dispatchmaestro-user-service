from django.db import models
from utils.constants import DELETED
from config.settings import cipher_suite

class EncryptedField(models.TextField):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def from_db_value(self, value, expression, connection):
        if value is None:
            return value
        return cipher_suite.decrypt(value.encode()).decode()

    def to_python(self, value):
        if value is None:
            return value
        return cipher_suite.decrypt(value.encode()).decode()

    def get_prep_value(self, value):
        if value is None:
            return value
        return cipher_suite.encrypt(value.encode()).decode()

class EncryptionHelper():

    @staticmethod
    def encrypt_data(data):
        encrypted_data = cipher_suite.encrypt(data.encode())
        return encrypted_data

    @staticmethod
    def decrypt_data(encrypted_data):
        decrypted_data = cipher_suite.decrypt(encrypted_data).decode()
        return decrypted_data
