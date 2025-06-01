import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from config.settings import CORE_BASE_URL

class DispatchMaestro():
    # # Class-level session to be reused
    # _session = None
    
    # @classmethod
    # def get_session(cls):
    #     if cls._session is None:
    #         cls._session = requests.Session()
            
    #         # Configure retries
    #         retry_strategy = Retry(
    #             total=3,  # number of retries
    #             backoff_factor=0.1,  # wait 0.1s * (2 ** (retry - 1)) between retries
    #             status_forcelist=[500, 502, 503, 504],  # retry on these status codes
    #             allowed_methods=["GET", "POST", "PUT", "DELETE"]  # retry on these methods
    #         )
            
    #         # Configure connection pooling
    #         adapter = HTTPAdapter(
    #             max_retries=retry_strategy,
    #             pool_connections=10,  # number of connection pools
    #             pool_maxsize=100  # max size of each pool
    #         )
            
    #         # Mount the adapter for both http and https
    #         cls._session.mount("http://", adapter)
    #         cls._session.mount("https://", adapter)
        
    #     return cls._session

    def __init__(self) -> None:
        self.base_url = CORE_BASE_URL
        self.client = requests.Session()

    def create_client(self, data):
        url = "{}/clients/".format(self.base_url)
        resp = self.client.post(url, json=data)
        resp.raise_for_status()
        return resp.json()

    def create_partner(self, data):
        url = "{}/partners/".format(self.base_url)
        resp = self.client.post(url, json=data)
        resp.raise_for_status()
        return resp.json()
    
    def get_client_info(self, entity_id):
        url = "{}/clients/{}".format(self.base_url, entity_id)
        resp = self.client.get(url)
        resp.raise_for_status()
        return resp.json()
    
    def get_partner_info(self, entity_id):
        url = "{}/partners/{}".format(self.base_url, entity_id)
        resp = self.client.get(url)
        resp.raise_for_status()
        return resp.json()
    
    def update_webhook_secret(self, data):
        url = "{}/clients/webhook".format(self.base_url)
        resp = self.client.put(url, json=data)
        resp.raise_for_status()
        return resp.json()

    def edit_client_info(self, entity_id, data):
        url = "{}/clients/".format(self.base_url)
        resp = self.client.put(url, json=data, params={"entity_id": entity_id})
        resp.raise_for_status()
        return resp.json()
    
    def edit_partner_info(self, entity_id, data):
        url = "{}/partners/".format(self.base_url)
        resp = self.client.put(url, json=data, params={"entity_id": entity_id})
        resp.raise_for_status()
        return resp.json()
