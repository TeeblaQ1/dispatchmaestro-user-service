from rest_framework.exceptions import APIException
from utils.constants import FAILED


class CustomHTTPError(APIException):
    status_code = 400
    default_detail = 'An error occurred.'
    default_code = 'internal_server_error'

    def __init__(self, detail=None, code=None):
        self.detail = detail or self.default_detail
        self.code = code or self.status_code

    def get_full_details(self):
        return {
            'status': FAILED,
            'error': {
                'reason': 'Bad Request',
                'message': self.detail
            }
        }
