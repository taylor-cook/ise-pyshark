import time
import requests
import pyshark
import urllib3
import redis
import asyncio
import argparse
import netifaces
import sys
import os
import psutil
import logging
import concurrent
from signal import SIGINT, SIGTERM
from pathlib import Path
from ise_pyshark import parser
from ise_pyshark import endpointsdb
from requests.auth import HTTPBasicAuth
from urllib3.exceptions import InsecureRequestWarning
# # Suppress only the single InsecureRequestWarning from urllib3 needed
urllib3.disable_warnings(InsecureRequestWarning)

logger = logging.getLogger(__name__)
headers = {'accept':'application/json','Content-Type':'application/json'}
default_filter = '!ipv6 && (ssdp || (http && http.user_agent != "") || xml || browser || (mdns && (dns.resp.type == 1 || dns.resp.type == 16)))'
capture_running = False
capture_count = 0
skipped_packet = 0

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

def get_ise_attributes():
    url_suffix = "/api/v1/endpoint-custom-attribute"
    try:
        response = requests.get(fqdn + url_suffix, headers=headers, auth=HTTPBasicAuth(username, password), verify=False)
        if response.status_code == 200:
            return response.json()
        else:
            logger.warning('Unable to gather ISE Custom Attributes.  Check provided credentials and verify required permissions')
            sys.exit(0)
    except requests.exceptions.RequestException as err:
        logger.warning(f"Unable to communicate with ISE server - {err}")
        logger.warning('Exiting ise-pyshark program')
        sys.exit(0)

def validate_attributes(output, vars):
    # Create a set of attribute names from the JSON output
    output_attribute_names = {item.get('attributeName') for item in output}
    
    # Check for missing attributes in the output
    for variable_name, variable_type in vars.items():
        if variable_name not in output_attribute_names:
            logger.warning(f"{variable_name} is missing from the configured ISE Custom Attributes.")
            create_ise_attribute(variable_name, variable_type)
    
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
                logger.debug(f"Custom Attribute {attribute_name} : {attribute_type} does NOT match the expected type. Expected {variables[attribute_name]}, got {attribute_type}.")
        else:
            logger.debug(f"Skipping Custom Attribute '{attribute_name}' as it is not required for this program.")

def create_ise_attribute(name, type):
    url = f'{fqdn}/api/v1/endpoint-custom-attribute'
    data = {"attributeName": name,"attributeType": type}
    try:
        response = requests.post(url, headers=headers, json=data, auth=HTTPBasicAuth(username, password), verify=False)
        if response.status_code == 200 or response.status_code == 201:
            logger.debug(f'api response = {response.json()}')
    except requests.exceptions.RequestException as err:
        logger.warning(f'Unable to create required ISE Custom Attributes - {err}')
        logger.warning('Exiting ise-pyshark program')
        sys.exit(0)
        
def get_ise_endpoint(mac):
    url = f'{fqdn}/api/v1/endpoint/{mac}'
    try:
        start_get = time.time()
        response = requests.get(url, headers=headers, auth=HTTPBasicAuth(username, password), verify=False)
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

def bulk_update_put(update):
    url = f'{fqdn}/api/v1/endpoint/bulk'
    try:
        response = requests.put(url, headers=headers, json=update, auth=HTTPBasicAuth(username, password), verify=False)
        logger.debug(f'api response = {response.json()}')
    except requests.exceptions.RequestException as err:
        logger.warning(f'unable to update endponits within ISE - {err}')

def bulk_update_post(update):
    url = f'{fqdn}/api/v1/endpoint/bulk'
    try:
        response = requests.post(url, headers=headers, json=update, auth=HTTPBasicAuth(username, password), verify=False)
        logger.debug(f'api response = {response.json()}')
    except requests.exceptions.RequestException as err:
        logger.warning(f'unable to update endponits within ISE - {err}')

def update_ise_endpoints(endpoints_db, redis_db):
    logger.debug(f'gather active endpoints - Start')
    start_time = time.time()
    results = endpoints_db.get_active_entries()
    logger.debug(f'number of redis entries: {redis_db.dbsize()}')
    if results:
        endpoint_updates = []
        endpoint_creates = []
        for row in results:
            attributes = {
                    "isepyDeviceID": row[8],
                    "isepyHostname": row[4].replace("’","'"),
                    "isepyVendor": row[5],
                    "isepyModel": row[6],
                    "isepyOS": row[7],
                    "isepyType": row[10],
                    "isepySerial": row[9],
                    "isepyProtocols": row[1],
                    "isepyIP": row[2],
                    "isepyCertainty" : str(row[11])+","+str(row[12])+","+str(row[13])+","+str(row[14])+","+str(row[15])+","+str(row[16])+","+str(row[17])+","+str(row[18])
                    }
            
            ## For every entry, check if Redis DB has record before sending API call to ISE
            if check_mac_redis_status(redis_db,row[0],attributes) == False:
                iseCustomAttrib = get_ise_endpoint(row[0])
                if iseCustomAttrib == "no_values":
                    update = { "customAttributes": attributes, "mac": row[0] }
                    endpoint_updates.append(update)
                elif iseCustomAttrib is None:
                    update = { "customAttributes": attributes, "mac": row[0] }
                    endpoint_creates.append(update)
                else:                  
                    ## If certainty score is weighted the same, check individual values for update
                    newData = False
                    oldCertainty = iseCustomAttrib['isepyCertainty'].split(',')
                    newCertainty = attributes['isepyCertainty'].split(',')
                    if len(oldCertainty) != len(newCertainty):
                        logger.debug(f"Certainty values are of different lengths for {row[0]}. Cannot compare.")
                    
                    if attributes['isepyCertainty'] == iseCustomAttrib['isepyCertainty']:
                        if attributes['isepyDeviceID'] != iseCustomAttrib['isepyDeviceID']:
                            logger.debug(f'endpoint DeviceID mismatch - local: {attributes['isepyDeviceID']} certainty {int(newCertainty[0])} and remote = {iseCustomAttrib['isepyDeviceID']} certainty {int(oldCertainty[0])}')
                            newData = True
                        if attributes['isepyHostname'] != iseCustomAttrib['isepyHostname']:
                            newData = True
                        if attributes['isepyVendor'] != iseCustomAttrib['isepyVendor']:
                            newData = True
                        if attributes['isepyModel'] != iseCustomAttrib['isepyModel']:
                            newData = True
                        if attributes['isepyOS'] != iseCustomAttrib['isepyOS']:
                            newData = True
                        if attributes['isepyType'] != iseCustomAttrib['isepyType']:
                            newData = True
                        if attributes['isepySerial'] != iseCustomAttrib['isepySerial']:
                            newData = True
                        if attributes['isepyProtocols'] != iseCustomAttrib['isepyProtocols']:
                            if str(attributes['isepyProtocols']) not in str(iseCustomAttrib['isepyProtocols']):
                                attributes['isepyProtocols'] = str(iseCustomAttrib['isepyProtocols'],', ',attributes['isepyProtocols'])
                            newData = True
                        if attributes['isepyIP'] != iseCustomAttrib['isepyIP']:
                            newData = True

                    ## Check if the existing ISE fields match the new attribute values
                    if attributes['isepyCertainty'] != iseCustomAttrib['isepyCertainty']:
                        logger.debug(f'different values for {row[0]}')
                        oldCertainty = iseCustomAttrib['isepyCertainty'].split(',')
                        newCertainty = attributes['isepyCertainty'].split(',')

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
        
        logger.debug(f'check for endpoint updates to ISE - Start')
        if len(endpoint_updates) > 0:
            logger.debug(f'creating, updating {len(endpoint_updates)} endpoints in ISE - Start')
            chunk_size = 500
            for i in range(0, len(endpoint_updates),chunk_size):
                chunk = endpoint_updates[i:i + chunk_size]
                bulk_update_put(chunk)
            logger.debug(f'updating {len(endpoint_updates)} endpoints in ISE - Completed')
        if len(endpoint_creates) > 0:
            logger.debug(f'creating {len(endpoint_creates)} new endpoints in ISE - Start')
            chunk_size = 500
            for i in range(0, len(endpoint_creates),chunk_size):
                chunk = endpoint_creates[i:i + chunk_size]
                bulk_update_post(chunk)
            logger.debug(f'creating {len(endpoint_creates)} new endpoints in ISE - Completed')
        if (len(endpoint_creates) + len(endpoint_updates)) == 0:
            logger.debug(f'no endpoints created or updated in ISE')
        end_time = time.time()
        logger.debug(f'check for endpoint updates to ISE - Completed {round(end_time - start_time,4)}sec')

### REDIS SECTION
def connect_to_redis():
    # Connect to Redis server
    r = redis.Redis(host='localhost', port=6379, db=0)
    return r

def check_mac_redis_status(redis_db, mac_address, values):
    # Check if MAC address exists in the database
    if redis_db.exists(mac_address):
        # Retrieve existing values
        existing_values = redis_db.hgetall(mac_address)
        existing_values_decoded = {k.decode('utf-8'): v.decode('utf-8') for k, v in existing_values.items()}
        
        # Compare existing values with new values
        if existing_values_decoded != values:
            logger.debug(f"redis MAC address {mac_address} exists and has different values")
            logger.debug(f'existing: {existing_values_decoded} - new values: {values}')
            return False
        else:
            # logger.debug(f"redis MAC address {mac_address} exists and already has the same values")
            ## Endpoint is up to date in Redis DB
            return True
    else:
        # Update the record if MAC address does not exist
        redis_db.hset(mac_address, mapping=values)
        logger.debug(f"redis MAC address {mac_address} added to the database with values")
        return False

def print_all_endpoints(redis_db):
    # Retrieve and print all MAC addresses and their values in the database
    keys = redis_db.keys('*')  # Get all keys in the database
    logger.debug('print all endpoints in Redis DB')
    for key in keys:
        key_str = key.decode('utf-8')
        if redis_db.type(key) == b'hash':  # Ensure the key is a hash
            values = redis_db.hgetall(key_str)
            values_decoded = {k.decode('utf-8'): v.decode('utf-8') for k, v in values.items()}
            logger.debug(f"MAC Address: {key_str}, Values: {values_decoded}")

def clear_redis_db(redis_db):
    # Clear all entries in the Redis database
    redis_db.flushdb()
    logger.debug('clearing of Redis DB - Complete')

### Process network packets using global Parser instance and dictionary of supported protocols
def process_packet(packet, highest_layer):
    try:
        ## Avoids any UDP/TCP.SEGMENT reassemblies and raw UDP/TCP packets
        if '_' in highest_layer:        
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
        logger.debug(f'error processing packet details {highest_layer}: {e}')

## Process a given PCAP(NG) file with a provided PCAP filter
def process_capture_file(capture_file, capture_filter):
    if Path(capture_file).exists():
        logger.debug(f'processing capture file: {capture_file}')
        start_time = time.perf_counter()
        capture = pyshark.FileCapture(capture_file, display_filter=capture_filter, only_summaries=False, include_raw=True, use_json=True)
        currentPacket = 0
        for packet in capture:
            ## Wrap individual packet processing within 'try' statement to avoid formatting issues crashing entire process
            try:
                process_packet(packet, packet.highest_layer)
            except TypeError as e:
                logger.debug(f'Error processing packet: {capture_file}, packet # {currentPacket}: TypeError: {e}')
            currentPacket += 1
        capture.close()
        end_time = time.perf_counter()
        logger.debug(f'processing capture file complete: execution time: {end_time - start_time:0.6f} : {currentPacket} packets processed ##')
    else:
        logger.debug(f'capture file not found: {capture_file}')

if __name__ == '__main__':
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter('%(asctime)s:%(name)s:%(levelname)s:%(message)s'))
    logger.addHandler(handler)
    logger.setLevel(logging.DEBUG)

    for modname in ['ise_pyshark.parser', 'ise_pyshark.endpointsdb', 'ise_pyshark.ouidb']:
        s_logger = logging.getLogger(modname)
        handler.setFormatter(logging.Formatter('%(asctime)s:%(name)s:%(levelname)s:%(message)s'))
        s_logger.addHandler(handler)
        s_logger.setLevel(logging.DEBUG)

    # ## Parse input from initial start
    # argparser = argparse.ArgumentParser(description="Provide ISE URL and API credentials.")
    # argparser.add_argument('-u', '--username', required=True, help='ISE API username')
    # argparser.add_argument('-p', '--password', required=True, help='ISE API password')
    # argparser.add_argument('-a', '--url', required=True, help='ISE URL')
    # argparser.add_argument('-f', '--file', required=True, help='The PCAP(NG) file to analyze')
    # args = argparser.parse_args()
    # ints = netifaces.interfaces()

    # if Path(args.file).exists() == False:
    #     logger.warning(f'Invalid capture file provided: {args.file}')
    #     sys.exit(1)

    # username = args.username
    # password = args.password
    # fqdn = 'https://' + args.url
    # filename = args.file

    username = 'api-admin'
    password = 'Password123'
    fqdn = 'https://10.0.1.90'
    filename = 'captures/HOMELAB.pcapng'

    
    ## Validate that defined ISE instance has Custom Attributes defined
    logger.warning(f'checking ISE custom attributes - Start')
    start_time = time.time()
    current_attribs = get_ise_attributes()
    validate_attributes(current_attribs, variables)
    end_time = time.time()
    logger.warning(f'existing ISE attribute verification - Completed: {round(end_time - start_time,4)}sec')

    logger.warning(f'SQLDB and Redis DB creation - Start')
    start_time = time.time()
    endpoints = endpointsdb()
    endpoints.create_database()
    redis_client = connect_to_redis()
    clear_redis_db(redis_client)
    end_time = time.time()
    logger.warning(f'SQLDB and Redis DB creation - Completed: {round(end_time - start_time,4)}sec')

    
    # ### PCAP PARSING SECTION
    print('### LOADING PCAP ###')
    start_time = time.time()
    process_capture_file(filename, default_filter)
    end_time = time.time()
    print(f'Time taken: {round(end_time - start_time,4)}sec')
    update_ise_endpoints(endpoints, redis_client)

    ## REDIS OUTPUT
    endpoints.view_all_entries()
    logger.debug(f'number of redis entries: {redis_client.dbsize()}')
    clear_redis_db(redis_client)
