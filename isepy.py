import time
import requests
import pyshark
import urllib3
from isepyshark.parser import parser
from isepyshark.endpointsdb import endpointsdb
# import pxgrid_pyshark
import json
# from pxgrid_pyshark import endpointsdb
# from pxgrid_pyshark import parser
from requests.auth import HTTPBasicAuth
# from requests.packages.urllib3.exceptions import InsecureRequestWarning
from urllib3.exceptions import InsecureRequestWarning
# # Suppress only the single InsecureRequestWarning from urllib3 needed
urllib3.disable_warnings(InsecureRequestWarning)

fqdn = "https://10.0.1.90"
headers = {'accept':'application/json','Content-Type':'application/json'}
username = 'api-admin'
password = 'Password123'
capture_file = "captures/simulation.pcapng"
default_filter = '!ipv6 && (ssdp || (http && http.user_agent != "") || xml || browser || (mdns && (dns.resp.type == 1 || dns.resp.type == 16)))'
# mac_filter = 'eth.addr == 20:cf:ae:55:e0:02'
# if mac_filter != '':
#     default_filter = mac_filter + ' && ' + default_filter
parser = parser()
packet_callbacks = {
    'mdns': parser.parse_mdns_v7,
    'xml': parser.parse_xml,
    'sip': parser.parse_sip,
    'ssdp': parser.parse_ssdp,
    'http': parser.parse_http,
    'browser': parser.parse_smb_browser,
}
variables = {'isepyVendor':'String',
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
        # Process the response if necessary
        print(response.json())
    else:
        print('Failed to send request.')
        print('Status code:', response.status_code)
        print('Response:', response.text)

def getEndpoint(mac):
    url = f'{fqdn}/api/v1/endpoint/{mac}'
    response = requests.get(url, headers=headers, auth=HTTPBasicAuth(username, password), verify=False)
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

def updateEndpoint(mac, update):
    url = f'{fqdn}/api/v1/endpoint/{mac}'
    response = requests.put(url, headers=headers, json=update, auth=HTTPBasicAuth(username, password), verify=False)
    print(response.json())

def bulkUpdatePUT(update):
    url = f'{fqdn}/api/v1/endpoint/bulk'
    response = requests.put(url, headers=headers, json=update, auth=HTTPBasicAuth(username, password), verify=False)
    print(response.json())

def bulkUpdatePOST(update):
    url = f'{fqdn}/api/v1/endpoint/bulk'
    response = requests.post(url, headers=headers, json=update, auth=HTTPBasicAuth(username, password), verify=False)
    print(response.json())

def compare_arrays(array1, array2):
    # Ensure both arrays are of the same length
    if len(array1) != len(array2):
        print("Arrays are of different lengths. Cannot compare.")
        return

    # Compare element-wise
    for i in range(len(array1)):
        # Convert strings to integers
        value1 = int(array1[i])
        value2 = int(array2[i])

        # Compare values and print the result
        if value1 > value2:
            print(f"Index {i}: Array1 has a higher value ({value1} > {value2})")
        elif value1 < value2:
            print(f"Index {i}: Array2 has a higher value ({value2} > {value1})")
        else:
            print(f"Index {i}: Both values are equal ({value1} = {value2})")

## Process network packets using global Parser instance and dictionary of supported protocols
def process_packet(packet):
    try:
        highest_layer = packet.highest_layer
        inspection_layer = str(highest_layer).split('_')[0]
        ## If XML traffic included over HTTP, match on XML parsing
        if inspection_layer == 'XML':
            fn = parser.parse_xml(packet)
            if fn is not None:
                endpoints.update_db_list(fn)
        else:
            for layer in packet.layers:
                fn = packet_callbacks.get(layer.layer_name)
                if fn is not None:
                    endpoints.update_db_list(fn(packet))
    except Exception as e:
        print(f'error processing packet details {highest_layer}: {e}')
        # logger.debug(f'error processing packet details {highest_layer}: {e}')

## Process a given PCAP(NG) file with a provided PCAP filter
def process_capture_file(capture_file, capture_filter):
    # if Path(capture_file).exists():
    #     logger.debug(f'processing capture file: {capture_file}')
    #     start_time = time.perf_counter()
        capture = pyshark.FileCapture(capture_file, display_filter=capture_filter, only_summaries=False, include_raw=True, use_json=True)
        currentPacket = 0
        for packet in capture:
            ## Wrap individual packet processing within 'try' statement to avoid formatting issues crashing entire process
            try:
                print(f'proccessing packet # {currentPacket}')
                # print(f'packet parsed {packet.highest_layer}')
                process_packet(packet)
            except TypeError as e:
                print(f'Error processing packet: {capture_file}, packet # {currentPacket}: TypeError: {e}')
                # logger.debug(f'Error processing packet: {capture_file}, packet # {currentPacket}: TypeError: {e}')
            currentPacket += 1
        capture.close()
        # end_time = time.perf_counter()
        # logger.debug(f'processing capture file complete: execution time: {end_time - start_time:0.6f} : {currentPacket} packets processed ##')
    # else:
    #     logger.debug(f'capture file not found: {capture_file}')

if __name__ == '__main__':
    ## Validate that defined ISE instance has Custom Attributes defined
    print('### CHECKING ISE ATTRIBUTES ###')
    start_time = time.time()
    current_attribs = getExistingAttributes()
    check_attributes(current_attribs, variables)
    end_time = time.time()
    print(f'Time taken: {end_time - start_time} seconds')

    print('### CREATING ENDPOINT DB ###')
    start_time = time.time()
    endpoints = endpointsdb()
    endpoints.create_database()
    end_time = time.time()
    print(f'Time taken: {end_time - start_time} seconds')
    
    print('### LOADING PCAP ###')
    start_time = time.time()
    process_capture_file(capture_file, default_filter)
    end_time = time.time()
    print(f'Time taken: {end_time - start_time} seconds')
    endpoints.view_all_entries()

    ## DISABLE FOR TESTING...
    # ''' 
    print('### GATHER ACTIVE ENDPOINTS')
    results = endpoints.get_active_entries()

    if results:
        endpoint_updates = []
        endpoint_creates = []
        for row in results:
            attributes = {
                    "isepyVendor": row[5],
                    "isepyModel": row[6],
                    "isepyOS": row[7],
                    "isepyType": row[10],
                    "isepySerial": row[9],
                    "isepyDeviceID": row[8],
                    "isepyHostname": row[4].replace("’","'"),
                    "isepyIP": row[2],
                    "isepyProtocols": row[1],
                    "isepyCertainty" : str(row[11])+","+str(row[12])+","+str(row[13])+","+str(row[14])+","+str(row[15])+","+str(row[16])+","+str(row[17])+","+str(row[18])
                    }

            iseCustomAttrib = getEndpoint(row[0])
            
            if iseCustomAttrib == "no_values":
                update = { "customAttributes": attributes, "mac": row[0] }
                endpoint_updates.append(update)

            elif iseCustomAttrib is None:
                update = { "customAttributes": attributes, "mac": row[0] }
                endpoint_creates.append(update)
            else:
                ### TODO -- Change logic to only if certainty is >= than existing certainty from ISE...
                ### if equal, but "newData" field resolves to "false", don't update
                ### if equal, but "newData" field resolves to "true", update
                
                ## Check if the existing ISE fields match the new attribute values
                if attributes['isepyCertainty'] != iseCustomAttrib['isepyCertainty']:
                    newData = False
                    print(f'different values for {row[0]}')
                    oldCertainty = iseCustomAttrib['isepyCertainty'].split(',')
                    newCertainty = attributes['isepyCertainty'].split(',')
                    if len(oldCertainty) != len(newCertainty):
                        print(f"Certainty values are of different lengths for {row[0]}. Cannot compare.")
                    # Compare element-wise
                    for i in range(len(oldCertainty)):
                        # Convert strings to integers
                        value1 = int(oldCertainty[i])
                        value2 = int(newCertainty[i])
                        if value2 > value1:
                            newData = True
                    if newData == True:
                        update = { "customAttributes": attributes, "mac": row[0] } 
                        endpoint_updates.append((update))
        
        print('### Checking for endpoint updates for ISE ###')
        start_time = time.time()
        if len(endpoint_updates) > 0:
            print(f'### Updating {len(endpoint_updates)} endpoints in ISE ###')
            chunk_size = 500
            for i in range(0, len(endpoint_updates),chunk_size):
                chunk = endpoint_updates[i:i + chunk_size]
                bulkUpdatePUT(chunk)
            # print(f'### endpoint_updates ###\n {json.dumps(endpoint_updates, ensure_ascii=False)}')
        if len(endpoint_creates) > 0:
            print(f'### Creating {len(endpoint_creates)} new endpoints in ISE ###')
            chunk_size = 500
            for i in range(0, len(endpoint_creates),chunk_size):
                chunk = endpoint_creates[i:i + chunk_size]
                bulkUpdatePOST(chunk)
            # print(f'### endpoint_updates ###\n {json.dumps(endpoint_creates, ensure_ascii=False)}')
        if (len(endpoint_creates) + len(endpoint_updates)) == 0:
            print('### No updates sent to ISE ###')
        end_time = time.time()
        print(f'Time taken: {end_time - start_time} seconds')
        # '''
