import urllib3
import sys
import logging
import requests
import time
from requests.auth import HTTPBasicAuth
from urllib3.exceptions import InsecureRequestWarning
# # Suppress only the single InsecureRequestWarning from urllib3 needed
urllib3.disable_warnings(InsecureRequestWarning)

logger = logging.getLogger(__name__)

api_call_total =0
ise_attributes = {'isepyVendor':'String',
             'isepyModel':'String',
             'isepyOS':'String',
             'isepyType':'String',
             'isepySerial':'String',
             'isepyDeviceID':'String',
             'isepyHostname':'String',
             'isepyIP':'IP',
             'isepyProtocols':'String',
             'isepyCertainty':'String'
            }

class apis:
    def __init__(self, fqdn, user, pwd, headers):
        ## TODO - check for multiple entries in FQDN field, and if multiple, include 'keep-alive' check for connectivity in case of failure
        self.fqdn = fqdn
        self.user = user
        self.pwd = pwd
        self.headers = headers
        # self._test_connection()
    
    # def _test_connection(self):
    #     logger.debug(f'testing API creds to {self.fqdn}')
        
    def get_ise_attributes(self):
        url_suffix = "/api/v1/endpoint-custom-attribute"
        try:
            response = requests.get(self.fqdn + url_suffix, headers=self.headers, auth=HTTPBasicAuth(self.user, self.pwd), verify=False)
            if response.status_code == 200:
                return response.json()
            else:
                logger.warning('Unable to gather ISE Custom Attributes.  Check provided credentials and verify required permissions')
                sys.exit(0)
        except requests.exceptions.RequestException as err:
            logger.warning(f"Unable to communicate with ISE server - {err}")
            logger.warning('Exiting ise-pyshark program')
            sys.exit(0)

    def validate_attributes(self, output, vars):
        # Create a set of attribute names from the JSON output
        output_attribute_names = {item.get('attributeName') for item in output}
        
        # Check for missing attributes in the output
        for variable_name, variable_type in vars.items():
            if variable_name not in output_attribute_names:
                logger.warning(f"{variable_name} is missing from the configured ISE Custom Attributes.")
                self.create_ise_attribute(variable_name, variable_type)
        
        # Iterate through each item in the output list
        for item in output:
            # Extract the attribute name and type from the item
            attribute_name = item.get('attributeName')
            attribute_type = item.get('attributeType')
            
            # Check if the attribute name is in the variables dictionary
            if attribute_name in vars:
                # Check if the attribute type matches the one in the variables dictionary
                if vars[attribute_name] == attribute_type:
                    logger.info(f"Custom Attribute {attribute_name} : {attribute_type} already defined.")
                else:
                    logger.warning(f"Custom Attribute {attribute_name} : {attribute_type} does NOT match the expected type. Expected {ise_attributes[attribute_name]}, got {attribute_type}.")
            else:
                logger.debug(f"Skipping Custom Attribute '{attribute_name}' as it is not required for this program.")

    def create_ise_attribute(self, name, type):
        url = f'{self.fqdn}/api/v1/endpoint-custom-attribute'
        data = {"attributeName": name,"attributeType": type}
        try:
            response = requests.post(url, headers=self.headers, json=data, auth=HTTPBasicAuth(self.user, self.pwd), verify=False)
            if response.status_code == 200 or response.status_code == 201:
                logger.debug(f'api response = {response.json()}')
        except requests.exceptions.RequestException as err:
            logger.warning(f'Unable to create required ISE Custom Attributes - {err}')
            logger.warning('Exiting ise-pyshark program')
            sys.exit(0)

    def get_ise_endpoint(self, mac):
        url = f'{self.fqdn}/api/v1/endpoint/{mac}'
        try:
            start_get = time.time()
            response = requests.get(url, headers=self.headers, auth=HTTPBasicAuth(self.user, self.pwd), verify=False)
            end_get = time.time()
            logger.debug(f'requesting ISE data for {mac} - ISE response time: {round(end_get - start_get,4)}sec')

            ## If an endpoint exists...
            if response.status_code != 404:
                defaults = {'isepyProtocols': '', 'isepyType': '', 'isepyDeviceID': '', 'isepyIP': '', 'isepyOS': '', 'isepyVendor': '', 'isepyModel': '', 'isepyHostname': '', 'isepyCertainty': '', 'isepySerial': ''}
                result = response.json()
                custom_attributes = result.get('customAttributes', {})
                if custom_attributes ==  None or custom_attributes == defaults:
                    return "no_values"
                elif custom_attributes != defaults:
                    custom_attributes_dict = {}
                    for key, value in custom_attributes.items():
                        custom_attributes_dict[key] = value
                    return custom_attributes
            else:
                return None
        except requests.exceptions.RequestException as err:
            logger.warning(f'An error occurred: {err}')
            return None

    def get_ise_endpoint_full(self, mac):
        url = f'{self.fqdn}/api/v1/endpoint/{mac}'
        try:
            start_get = time.time()
            response = requests.get(url, headers=self.headers, auth=HTTPBasicAuth(self.user, self.pwd), verify=False)
            end_get = time.time()
            logger.debug(f'requesting ISE data for {mac} - ISE response time: {round(end_get - start_get,4)}sec')
            ## If an endpoint exists, return the full endpoint API response...
            if response.status_code != 404:
                return response.json()
            else:
                return None
        except requests.exceptions.RequestException as err:
            logger.warning(f'An error occurred: {err}')
            return None

    def bulk_update_put(self, update):
        url = f'{self.fqdn}/api/v1/endpoint/bulk'
        try:
            response = requests.put(url, headers=self.headers, json=update, auth=HTTPBasicAuth(self.user, self.pwd), verify=False)
            logger.info(f'endpoint bulk update api response = {response.json()}')
        except requests.exceptions.RequestException as err:
            logger.warning(f'unable to update endpoints within ISE - {err}')

    def bulk_update_post(self, update):
        url = f'{self.fqdn}/api/v1/endpoint/bulk'
        try:
            response = requests.post(url, headers=self.headers, json=update, auth=HTTPBasicAuth(self.user, self.pwd), verify=False)
            logger.info(f'endpoint bulk create api response = {response.json()}')
        except requests.exceptions.RequestException as err:
            logger.warning(f'unable to update endpoints within ISE - {err}')

    async def get_ise_endpoint_async(self, mac):
        url = f'{self.fqdn}/api/v1/endpoint/{mac}'
        try:
            start_get = time.time()
            response = requests.get(url, headers=self.headers, auth=HTTPBasicAuth(self.user, self.pwd), verify=False)
            end_get = time.time()
            logger.debug(f'API call to ISE for {mac} - ISE response time: {round(end_get - start_get,4)}sec')
            ## If an endpoint exists...
            if response.status_code != 404:
                result = response.json()
                custom_attributes = result.get('customAttributes', {})
                if custom_attributes ==  None:
                    return "no_values"
                else:
                    custom_attributes_dict = {}
                    for key, value in custom_attributes.items():
                        custom_attributes_dict[key] = value
                    return custom_attributes
            else:
                return None
        except requests.exceptions.RequestException as err:
            logger.warning(f'An error occurred: {err}')
            return None

    async def get_ise_endpoint_full_async(self, mac):
        url = f'{self.fqdn}/api/v1/endpoint/{mac}'
        try:
            start_get = time.time()
            response = requests.get(url, headers=self.headers, auth=HTTPBasicAuth(self.user, self.pwd), verify=False)
            end_get = time.time()
            logger.debug(f'API call to ISE for {mac} - ISE response time: {round(end_get - start_get,4)}sec')
            ## If an endpoint exists, return the full endpoint API response...
            if response.status_code != 404:
                return response.json()
            else:
                return None
        except requests.exceptions.RequestException as err:
            logger.warning(f'An error occurred: {err}')
            return None

    async def bulk_update_put_async(self, update):
        url = f'{self.fqdn}/api/v1/endpoint/bulk'
        try:
            response = requests.put(url, headers=self.headers, json=update, auth=HTTPBasicAuth(self.user, self.pwd), verify=False)
            logger.info(f'endpoint bulk update api response = {response.json()}')
        except requests.exceptions.RequestException as err:
            logger.warning(f'unable to update endpoints within ISE - {err}')

    async def bulk_update_post_async(self, update):
        url = f'{self.fqdn}/api/v1/endpoint/bulk'
        try:
            response = requests.post(url, headers=self.headers, json=update, auth=HTTPBasicAuth(self.user, self.pwd), verify=False)
            logger.info(f'endpoint bulk create api response = {response.json()}')
        except requests.exceptions.RequestException as err:
            logger.warning(f'unable to update endpoints within ISE - {err}')