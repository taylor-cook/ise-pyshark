import requests
import json
from requests.auth import HTTPBasicAuth
# from requests.packages.urllib3.exceptions import InsecureRequestWarning

# # Suppress only the single InsecureRequestWarning from urllib3 needed
# requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


fqdn = "https://10.0.1.85"
# url = "https://10.0.1.85/api/v1/endpoint-custom-attribute"
headers = {'Content-Type':'application/json'}
username = 'api-admin'
password = 'Password123'

# variables = {'PanwIoTProfile':'String',
#              'PanwIoTCategory':'String',
#              'PanwIoTTag':'String',
#              'PanwIoTHostname':'String',
#              'PanwIoTOS':'String',
#              'PanwIoTModel':'String',
#              'PanwIoTVendor':'String',
#              'PanwIoTSerial':'String',
#              'PanwIoTEPP':'String',
#              'PanwIoTAET':'String',
#              'PanwIoTInternetAccess':'String',
#              'PanwIoTIP':'IP',
#              'PanwIoTRiskScore':'Int',
#              'PanwIoTConfidence':'Int'
#             }

variables = {'isepyVendor':'String',
             'isepyModel':'String',
             'isepyOS':'String',
             'isepyType':'String',
             'isepySerial':'String',
             'isepyDeviceID':'String',
             'isepyHostname':'String',
             'isepyIP':'IP',
             'isepyCertainty':'Int'
            }
newVariables = {}

def getExistingAttributes():
    url_suffix = "/api/v1/endpoint-custom-attribute"
    response = requests.get(fqdn + url_suffix, headers=headers, auth=HTTPBasicAuth(username, password), verify=False)
    if response.status_code == 200:
        return response.json()
        # print(json.loads(response.content))
    else:
        print('Failed to send request.')
        print('Status code:', response.status_code)
        print('Response:', response.text)

def check_attributes(output, vars):
    # Create a set of attribute names from the JSON output
    output_attribute_names = {item.get('attributeName') for item in output}
    
    # Check for missing attributes in the output
    for variable_name, variable_type in vars.items():
        if variable_name not in output_attribute_names:
            print(f"Alert: {variable_name} is missing from the output.")
            createAttribute(variable_name, variable_type)
    
    # Iterate through each item in the output list
    for item in output:
        # Extract the attribute name and type from the item
        attribute_name = item.get('attributeName')
        attribute_type = item.get('attributeType')
        
        # Check if the attribute name is in the variables dictionary
        if attribute_name in vars:
            # Check if the attribute type matches the one in the variables dictionary
            if vars[attribute_name] == attribute_type:
                print(f"Custom Attribute {attribute_name} : {attribute_type} already defined.")
            else:
                print(f"Custom Attribute {attribute_name} : {attribute_type} does NOT match the expected type. Expected {variables[attribute_name]}, got {attribute_type}.")
        else:
            print(f"{attribute_name} is not a recognized attribute.")

def createAttribute(name, type):
    url = f'{fqdn}/api/v1/endpoint-custom-attribute'
    data = {"attributeName": name,"attributeType": type}
    response = requests.post(url, headers=headers, json=data, auth=HTTPBasicAuth(username, password), verify=False)
    if response.status_code == 200:
        # print('Success!')
        # Process the response if necessary
        print(response.json())
    else:
        print('Failed to send request.')
        print('Status code:', response.status_code)
        print('Response:', response.text)

def getEndpoint(mac):
    url = f'{fqdn}/api/v1/endpoint/{mac}'
    response = requests.get(url, headers=headers, auth=HTTPBasicAuth(username, password), verify=False)
    print(response.json())

def updateEndpoint(mac, update):
    url = f'{fqdn}/api/v1/endpoint/{mac}'
    response = requests.put(url, headers=headers, json=update, auth=HTTPBasicAuth(username, password), verify=False)
    print(response.json())

def bulkUpdate(update):
    url = f'{fqdn}/api/v1/endpoint/bulk'
    response = requests.put(url, headers=headers, json=update, auth=HTTPBasicAuth(username, password), verify=False)
    print(response.json())


# def createAttribute(value):
#     response = requests.post(url, headers=headers, data=value, auth=HTTPBasicAuth(username, password), verify=False)
#     if response.status_code == 200:
#         # print('Success!')
#         # Process the response if necessary
#         print(response.json())
#     else:
#         print('Failed to send request.')
#         print('Status code:', response.status_code)
#         print('Response:', response.text)

# for key, value in variables.items():
#     newVariables['attributeName'] = key
#     newVariables['attributeType'] = value
#     createAttribute(json.dumps(newVariables))

current_attribs = getExistingAttributes()
check_attributes(current_attribs, variables)

getEndpoint('30:59:B7:EB:9D:5B')
endpoint_list = []

update = {
  "customAttributes": { "isepyVendor" : "Microsoft" },
  "mac": "30:59:B7:EB:9D:5B"
}
endpoint_list.append(update)
update = {
  "customAttributes": { "isepyVendor" : "Apple" },
  "mac": "8C:7A:AA:EA:8B:8A"
}
endpoint_list.append(update)
# updateEndpoint('30:59:B7:EB:9D:5B', update)
print(endpoint_list)
bulkUpdate(endpoint_list)
    
# response = requests.post(url, headers=headers, data=json_data, auth=HTTPBasicAuth(username, password), verify=False)
# if response.status_code == 200:
#     print('Success!')
#     # Process the response if necessary
#     print(response.json())
# else:
#     print('Failed to send request.')
#     print('Status code:', response.status_code)
#     print('Response:', response.text)