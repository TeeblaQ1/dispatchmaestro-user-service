from rest_framework.views import exception_handler
from rest_framework.response import Response
from rest_framework.exceptions import ValidationError, ParseError
from utils.constants import FAILED
from utils.classes.exceptions import CustomHTTPError
from requests.exceptions import HTTPError

def custom_exception_handler(exc, context):
    # Customize the error response here
    response = exception_handler(exc, context)

    if response is not None:

        if isinstance(exc, ValidationError):
            return Response({
                "status": FAILED,
                "error": {
                    "reason": response.status_text,
                    "message": response.data[0] if len(response.data) > 0 else response.status_text
                }
            }, status=response.status_code)
        elif isinstance(exc, CustomHTTPError):
            response.data = exc.get_full_details()
            return response
        return Response({
                "status": response.data.get("status", "INTERNAL_SERVER_ERROR"),
                "error": {
                    "reason": response.status_text,
                    "message": response.data.get("detail")
                }
            }, status=response.status_code)
    return response
