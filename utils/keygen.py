import os
import base64
from config.settings import cipher_suite

def generate_public_key():
    return base64.urlsafe_b64encode(os.urandom(32))[:32].decode().upper()

def generate_apikeys():
    return cipher_suite.encrypt(generate_public_key().encode()).decode()
