import adal
from modules.constants import url_const
import json


class TokenGenerator:

    def __init__(self, tenant_id):
        """ To initialize context with tenant_id

        Args:

        tenant_id  : str - The tenant id for the azure account.

        """
        self.CONTEXT = adal.AuthenticationContext(
            url_const.AUTHORITY_URL.format(tenant_id))

    def management_token_generator(self, client_id, client_secrect):
        """ To generate management token using this method in order to access

            Args:

            client_id       : str - The client id from azure account.\n
            client_secrect  : str - The client_secrect from azure.

            Returns:

            str : accessToken - The access token.
        """
        entire_token = self.CONTEXT.acquire_token_with_client_credentials(url_const.MGMT_RESOURCE,
                                                                          client_id, client_secrect)
        return entire_token["accessToken"]

    def storage_token_generator(self, client_id, client_secrect):
        """ To generate storage token using this method in order to access

            Args:

            client_id       : str - The client id from azure account.\n
            client_secrect  : str - The client_secrect from azure.

            Returns:

            str : accessToken - The access token.

        """
        entire_token = self.CONTEXT.acquire_token_with_client_credentials(url_const.STORAGE_RESOURCE,
                                                                          client_id, client_secrect)

        return entire_token["accessToken"]
    
    def vault_token_generator(self, client_id, client_secrect):

        entire_token = self.CONTEXT.acquire_token_with_client_credentials(url_const.VAULT_RESOURCE,
                                                                          client_id, client_secrect)

        return entire_token["accessToken"]
