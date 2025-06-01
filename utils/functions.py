from apps.clients.models import Client
import random
import re
import datetime
import hmac
import hashlib

from config.settings import COST_PER_KM, SERVICE_CHARGE, APP_SECRET

def validate_signature(payload, signature):
    """
    Validate the incoming payload's signature against our expected signature
    """
    # Use the App Secret to hash the payload
    expected_signature = hmac.new(
        bytes(APP_SECRET, "latin-1"),
        msg=payload.encode("utf-8"),
        digestmod=hashlib.sha256,
    ).hexdigest()

    # Check if the signature matches
    return hmac.compare_digest(expected_signature, signature)

def convert_amount_to_naira(amount: int | float, comma_sep=False):
    return "{:0,.2f}".format(amount / 100) if comma_sep else "{:.2f}".format(amount / 100)

def calculate_max_distance_route(routes: list):
    max_distance = 0
    max_distance_route = None
    for route in routes:
        distance = route["distance"]
        if distance > max_distance:
            max_distance = distance
            max_distance_route = route
    
    return max_distance_route

def round_nth_decimal_places(number, places=2):
    return round(number, places)

def round_to_nearest_n(number, n=10000):
    return round(number / n) * n

def generate_random_warehouse_name(client: Client):
    business_name = Client.business_name
    # Split the business name into words
    words = re.findall(r'\b\w+\b', business_name)

    # Randomly select a word from the business name
    selected_word = random.choice(words)

    # Generate a random suffix for the warehouse name
    suffix = ''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=3))

    # Combine the selected word and suffix to form the warehouse name
    warehouse_name = f'{selected_word}_{suffix}'
    return warehouse_name

def convert_to_two_digits(number):
    if number < 10:
        return f"0{number}"
    else:
        return str(number)

def format_date_range(start_date, end_date):
    # Format the dates in "Month Day" format
    formatted_start_date = start_date.strftime("%b %d")
    formatted_end_date = end_date.strftime("%b %d")

    # Check if the start and end dates are in the same month
    if start_date.month == end_date.month:
        date_range = f"{formatted_start_date} - {convert_to_two_digits(end_date.day)}"
    else:
        date_range = f"{formatted_start_date} - {formatted_end_date}"
    
    return date_range

def calculate_shipment_cost(distance):
    return round_to_nearest_n((distance * int(COST_PER_KM)) + int(SERVICE_CHARGE))


def normalize_status(status: str):
    return " ".join(status.split("_")).title()