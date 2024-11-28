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
                self.create_ise_attribute(self, variable_name, variable_type)
        
        # Iterate through each item in the output list
        for item in output:
            # Extract the attribute name and type from the item
            attribute_name = item.get('attributeName')
            attribute_type = item.get('attributeType')
            
            # Check if the attribute name is in the variables dictionary
            if attribute_name in vars:
                # Check if the attribute type matches the one in the variables dictionary
                if vars[attribute_name] == attribute_type:
                    logger.debug(f"Custom Attribute {attribute_name} : {attribute_type} already defined.")
                else:
                    logger.debug(f"Custom Attribute {attribute_name} : {attribute_type} does NOT match the expected type. Expected {ise_attributes[attribute_name]}, got {attribute_type}.")
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
            logger.debug(f'An error occurred: {err}')
            return None

    def bulk_update_put(self, update):
        url = f'{self.fqdn}/api/v1/endpoint/bulk'
        try:
            response = requests.put(url, headers=self.headers, json=update, auth=HTTPBasicAuth(self.user, self.pwd), verify=False)
            logger.debug(f'api response = {response.json()}')
        except requests.exceptions.RequestException as err:
            logger.warning(f'unable to update endponits within ISE - {err}')

    def bulk_update_post(self, update):
        url = f'{self.fqdn}/api/v1/endpoint/bulk'
        try:
            response = requests.post(url, headers=self.headers, json=update, auth=HTTPBasicAuth(self.user, self.pwd), verify=False)
            logger.debug(f'api response = {response.json()}')
        except requests.exceptions.RequestException as err:
            logger.warning(f'unable to update endponits within ISE - {err}')

    # def update_ise_endpoints(self, endpoints_db, redis_db):
    #     logger.debug(f'gather active endpoints - Start')
    #     start_time = time.time()
    #     results = endpoints_db.get_active_entries()
    #     logger.debug(f'number of redis entries: {redis_db.dbsize()}')
    #     if results:
    #         endpoint_updates = []
    #         endpoint_creates = []
    #         for row in results:
    #             attributes = {
    #                     "isepyDeviceID": row[8],
    #                     "isepyHostname": row[4].replace("’","'"),
    #                     "isepyVendor": row[5],
    #                     "isepyModel": row[6],
    #                     "isepyOS": row[7],
    #                     "isepyType": row[10],
    #                     "isepySerial": row[9],
    #                     "isepyProtocols": row[1],
    #                     "isepyIP": row[2],
    #                     "isepyCertainty" : str(row[11])+","+str(row[12])+","+str(row[13])+","+str(row[14])+","+str(row[15])+","+str(row[16])+","+str(row[17])+","+str(row[18])
    #                     }
                
    #             ## For every entry, check if Redis DB has record before sending API call to ISE
    #             if self.check_mac_redis_status(redis_db,row[0],attributes) == False:
    #                 iseCustomAttrib = self.get_ise_endpoint(row[0])
    #                 if iseCustomAttrib == "no_values":
    #                     update = { "customAttributes": attributes, "mac": row[0] }
    #                     endpoint_updates.append(update)
    #                 elif iseCustomAttrib is None:
    #                     update = { "customAttributes": attributes, "mac": row[0] }
    #                     endpoint_creates.append(update)
    #                 else:                  
    #                     ## If certainty score is weighted the same, check individual values for update
    #                     newData = False
    #                     oldCertainty = iseCustomAttrib['isepyCertainty'].split(',')
    #                     newCertainty = attributes['isepyCertainty'].split(',')
    #                     if len(oldCertainty) != len(newCertainty):
    #                         logger.debug(f"Certainty values are of different lengths for {row[0]}. Cannot compare.")
                        
    #                     if attributes['isepyCertainty'] == iseCustomAttrib['isepyCertainty']:
    #                         if attributes['isepyDeviceID'] != iseCustomAttrib['isepyDeviceID']:
    #                             logger.debug(f'endpoint DeviceID mismatch - local: {attributes['isepyDeviceID']} certainty {int(newCertainty[0])} and remote = {iseCustomAttrib['isepyDeviceID']} certainty {int(oldCertainty[0])}')
    #                             newData = True
    #                         if attributes['isepyHostname'] != iseCustomAttrib['isepyHostname']:
    #                             newData = True
    #                         if attributes['isepyVendor'] != iseCustomAttrib['isepyVendor']:
    #                             newData = True
    #                         if attributes['isepyModel'] != iseCustomAttrib['isepyModel']:
    #                             newData = True
    #                         if attributes['isepyOS'] != iseCustomAttrib['isepyOS']:
    #                             newData = True
    #                         if attributes['isepyType'] != iseCustomAttrib['isepyType']:
    #                             newData = True
    #                         if attributes['isepySerial'] != iseCustomAttrib['isepySerial']:
    #                             newData = True
    #                         if attributes['isepyProtocols'] != iseCustomAttrib['isepyProtocols']:
    #                             if str(attributes['isepyProtocols']) not in str(iseCustomAttrib['isepyProtocols']):
    #                                 attributes['isepyProtocols'] = str(iseCustomAttrib['isepyProtocols'],', ',attributes['isepyProtocols'])
    #                             newData = True
    #                         if attributes['isepyIP'] != iseCustomAttrib['isepyIP']:
    #                             newData = True

    #                     ## Check if the existing ISE fields match the new attribute values
    #                     if attributes['isepyCertainty'] != iseCustomAttrib['isepyCertainty']:
    #                         logger.debug(f'different values for {row[0]}')
    #                         oldCertainty = iseCustomAttrib['isepyCertainty'].split(',')
    #                         newCertainty = attributes['isepyCertainty'].split(',')

    #                         # Compare element-wise
    #                         for i in range(len(oldCertainty)):
    #                             # Convert strings to integers
    #                             value1 = int(oldCertainty[i])
    #                             value2 = int(newCertainty[i])
    #                             if value2 > value1:
    #                                 newData = True
    #                     if newData == True:
    #                         update = { "customAttributes": attributes, "mac": row[0] } 
    #                         endpoint_updates.append((update))
            
    #         logger.debug(f'check for endpoint updates to ISE - Start')
    #         if len(endpoint_updates) > 0:
    #             logger.debug(f'creating, updating {len(endpoint_updates)} endpoints in ISE - Start')
    #             chunk_size = 500
    #             for i in range(0, len(endpoint_updates),chunk_size):
    #                 chunk = endpoint_updates[i:i + chunk_size]
    #                 self.bulk_update_put(chunk)
    #             logger.debug(f'updating {len(endpoint_updates)} endpoints in ISE - Completed')
    #         if len(endpoint_creates) > 0:
    #             logger.debug(f'creating {len(endpoint_creates)} new endpoints in ISE - Start')
    #             chunk_size = 500
    #             for i in range(0, len(endpoint_creates),chunk_size):
    #                 chunk = endpoint_creates[i:i + chunk_size]
    #                 self.bulk_update_post(chunk)
    #             logger.debug(f'creating {len(endpoint_creates)} new endpoints in ISE - Completed')
    #         if (len(endpoint_creates) + len(endpoint_updates)) == 0:
    #             logger.debug(f'no endpoints created or updated in ISE')
    #         end_time = time.time()
    #         logger.debug(f'check for endpoint updates to ISE - Completed {round(end_time - start_time,4)}sec')

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
                    # print(f'API response for {mac}: {custom_attributes}')
                    custom_attributes_dict = {}
                    for key, value in custom_attributes.items():
                        custom_attributes_dict[key] = value
                    return custom_attributes
            else:
                return None
        except requests.exceptions.RequestException as err:
            logger.debug(f'An error occurred: {err}')
            return None

    async def bulk_update_put_async(self, update):
        url = f'{self.fqdn}/api/v1/endpoint/bulk'
        try:
            response = requests.put(url, headers=self.headers, json=update, auth=HTTPBasicAuth(self.user, self.pwd), verify=False)
            logger.debug(f'api response = {response.json()}')
        except requests.exceptions.RequestException as err:
            logger.warning(f'unable to update endponits within ISE - {err}')

    async def bulk_update_post_async(self, update):
        url = f'{self.fqdn}/api/v1/endpoint/bulk'
        try:
            response = requests.post(url, headers=self.headers, json=update, auth=HTTPBasicAuth(self.user, self.pwd), verify=False)
            logger.debug(f'api response = {response.json()}')
        except requests.exceptions.RequestException as err:
            logger.warning(f'unable to update endponits within ISE - {err}')