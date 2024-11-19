import time
import requests
import pyshark
import urllib3
import redis
import asyncio
import argparse
import netifaces
import sys
from signal import SIGINT, SIGTERM
from ise_pyshark.parser import parser
from ise_pyshark.endpointsdb import endpointsdb
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
default_bpf_filter = "(ip proto 0x2f || tcp port 80 || tcp port 8080 || udp port 1900 || udp port 138 || udp port 5060 || udp port 5353) and not ip6"
capture_running = False
capture_count = 0
skipped_packet = 0

# mac_filter = 'eth.addr == BC:14:85:E5:CC:07'
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

def get_ise_attributes():
    url_suffix = "/api/v1/endpoint-custom-attribute"
    try:
        response = requests.get(fqdn + url_suffix, headers=headers, auth=HTTPBasicAuth(username, password), verify=False)
        if response.status_code == 200:
            return response.json()
        else:
            print("Unable to gather ISE Custom Attributes.  Check provided credentials and verify required permissions")
            sys.exit(0)
    except requests.exceptions.RequestException as err:
        print(f"An error occurred: {err}")
        print(f"Unable to communicate with ISE server. Exiting program.")
        sys.exit(0)

def validate_attributes(output, vars):
    # Create a set of attribute names from the JSON output
    output_attribute_names = {item.get('attributeName') for item in output}
    
    # Check for missing attributes in the output
    for variable_name, variable_type in vars.items():
        if variable_name not in output_attribute_names:
            print(f"ALERT: {variable_name} is missing from the configured ISE Custom Attributes.")
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
                print(f"Custom Attribute {attribute_name} : {attribute_type} already defined.")
            else:
                print(f"Custom Attribute {attribute_name} : {attribute_type} does NOT match the expected type. Expected {variables[attribute_name]}, got {attribute_type}.")
        else:
            print(f"Skipping Custom Attribute '{attribute_name}' as it is not required for this program.")

def create_ise_attribute(name, type):
    url = f'{fqdn}/api/v1/endpoint-custom-attribute'
    data = {"attributeName": name,"attributeType": type}
    try:
        response = requests.post(url, headers=headers, json=data, auth=HTTPBasicAuth(username, password), verify=False)
        if response.status_code == 200 or response.status_code == 201:
            print(response.json())
    except requests.exceptions.RequestException as err:
        print(f'An error occurred: {err}')
        print('Unable to create required ISE Custom Attributes.  Exiting program.')
        sys.exit(0)

def get_ise_endpoint(mac):
    url = f'{fqdn}/api/v1/endpoint/{mac}'
    try:
        response = requests.get(url, headers=headers, auth=HTTPBasicAuth(username, password), verify=False)
        print(f'requesting ISE data for {mac}')
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
        print(f'An error occurred: {err}')
        return None

async def get_ise_endpoint_async(mac):
    url = f'{fqdn}/api/v1/endpoint/{mac}'
    try:
        response = requests.get(url, headers=headers, auth=HTTPBasicAuth(username, password), verify=False)
        print(f'requesting ISE data for {mac}')
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
        print(f'An error occurred: {err}')
        return None

def bulk_update_put(update):
    url = f'{fqdn}/api/v1/endpoint/bulk'
    try:
        response = requests.put(url, headers=headers, json=update, auth=HTTPBasicAuth(username, password), verify=False)
        print(response.json())
    except requests.exceptions.RequestException as err:
        print(f'An error occurred: {err}')
        print('WARNING: Unable to update endponits within ISE')

async def bulk_update_put_async(update):
    url = f'{fqdn}/api/v1/endpoint/bulk'
    try:
        response = requests.put(url, headers=headers, json=update, auth=HTTPBasicAuth(username, password), verify=False)
        print(response.json())
    except requests.exceptions.RequestException as err:
        print(f'An error occurred: {err}')
        print('WARNING: Unable to update endponits within ISE')

def bulk_update_post(update):
    url = f'{fqdn}/api/v1/endpoint/bulk'
    try:
        response = requests.post(url, headers=headers, json=update, auth=HTTPBasicAuth(username, password), verify=False)
        print(response.json())
    except requests.exceptions.RequestException as err:
        print(f'An error occurred: {err}')
        print('WARNING: Unable to update endponits within ISE')

async def bulk_update_post_async(update):
    url = f'{fqdn}/api/v1/endpoint/bulk'
    try:
        response = requests.post(url, headers=headers, json=update, auth=HTTPBasicAuth(username, password), verify=False)
        print(response.json())
    except requests.exceptions.RequestException as err:
        print(f'An error occurred: {err}')
        print('WARNING: Unable to update endponits within ISE')

def update_ise_endpoints(endpoints_db, redis_db):
    print('### GATHER ACTIVE ENDPOINTS')
    start_time = time.time()
    results = endpoints_db.get_active_entries()
    print(f'number of redis entries: {redis_db.dbsize()}')
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
            
            ## For every entry, check if REDIS DB has record before sending API call to ISE
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
                        print(f"Certainty values are of different lengths for {row[0]}. Cannot compare.")
                    
                    if attributes['isepyCertainty'] == iseCustomAttrib['isepyCertainty']:
                        i = 0
                        for key in attributes:
                            if attributes.get(key) != iseCustomAttrib.get(key):
                                print(f'mismatch between local = {attributes.get(key)} certainty {int(newCertainty[i])} and remote = {iseCustomAttrib.get(key)} certainty {int(oldCertainty[i])} ')
                                newData = True
                            i += 1

                    ## Check if the existing ISE fields match the new attribute values
                    if attributes['isepyCertainty'] != iseCustomAttrib['isepyCertainty']:
                        print(f'different values for {row[0]}')
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
        
        print('### Checking for endpoint updates for ISE ###')
        if len(endpoint_updates) > 0:
            print(f'### Updating {len(endpoint_updates)} endpoints in ISE ###')
            chunk_size = 500
            for i in range(0, len(endpoint_updates),chunk_size):
                chunk = endpoint_updates[i:i + chunk_size]
                bulk_update_put(chunk)
            # print(f'### endpoint_updates ###\n {json.dumps(endpoint_updates, ensure_ascii=False)}')
        if len(endpoint_creates) > 0:
            print(f'### Creating {len(endpoint_creates)} new endpoints in ISE ###')
            chunk_size = 500
            for i in range(0, len(endpoint_creates),chunk_size):
                chunk = endpoint_creates[i:i + chunk_size]
                bulk_update_post(chunk)
            # print(f'### endpoint_updates ###\n {json.dumps(endpoint_creates, ensure_ascii=False)}')
        if (len(endpoint_creates) + len(endpoint_updates)) == 0:
            print('### No updates sent to ISE ###')
        end_time = time.time()
        print(f'Time taken: {end_time - start_time} seconds')
        # '''

async def update_ise_endpoints_async(endpoints_db, redis_db):
    print('### GATHER ACTIVE ENDPOINTS')
    start_time = time.time()
    results = await endpoints_db.get_active_entries_async()
    print(f'number of redis entries: {redis_db.dbsize()}')
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
            
            ## For every entry, check if REDIS DB has record before sending API call to ISE
            status = await check_mac_redis_status_async(redis_db,row[0],attributes)
            if status == False:
                iseCustomAttrib = await get_ise_endpoint_async(row[0])

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
                        print(f"Certainty values are of different lengths for {row[0]}. Cannot compare.")
                    
                    if attributes['isepyCertainty'] == iseCustomAttrib['isepyCertainty']:
                        i = 0
                        for key in attributes:
                            if attributes.get(key) != iseCustomAttrib.get(key):
                                print(f'mismatch between local = {attributes.get(key)} certainty {int(newCertainty[i])} and remote = {iseCustomAttrib.get(key)} certainty {int(oldCertainty[i])} ')
                                newData = True
                            i += 1

                    ## Check if the existing ISE fields match the new attribute values
                    if attributes['isepyCertainty'] != iseCustomAttrib['isepyCertainty']:
                        print(f'different values for {row[0]}')
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
        
        print('### Checking for endpoint updates for ISE ###')
        if len(endpoint_updates) > 0:
            print(f'### Updating {len(endpoint_updates)} endpoints in ISE ###')
            chunk_size = 500
            for i in range(0, len(endpoint_updates),chunk_size):
                chunk = endpoint_updates[i:i + chunk_size]
                result = await bulk_update_put_async(chunk)
            # print(f'### endpoint_updates ###\n {json.dumps(endpoint_updates, ensure_ascii=False)}')
        if len(endpoint_creates) > 0:
            print(f'### Creating {len(endpoint_creates)} new endpoints in ISE ###')
            chunk_size = 500
            for i in range(0, len(endpoint_creates),chunk_size):
                chunk = endpoint_creates[i:i + chunk_size]
                result = await bulk_update_post_async(chunk)
            # print(f'### endpoint_updates ###\n {json.dumps(endpoint_creates, ensure_ascii=False)}')
        if (len(endpoint_creates) + len(endpoint_updates)) == 0:
            print('### No updates sent to ISE ###')
        end_time = time.time()
        print(f'Time taken: {end_time - start_time} seconds')
        # '''

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
            print(f"redis MAC address {mac_address} exists and has different values")
            return False
        else:
            print(f"redis MAC address {mac_address} exists and has same values")
            ## Endpoint is up to date in Redis DB
            return True
    else:
        # Update the record if MAC address does not exist
        redis_db.hset(mac_address, mapping=values)
        print(f"redis MAC address {mac_address} added to the database with values")
        return False

async def check_mac_redis_status_async(redis_db, mac_address, values):
    # Check if MAC address exists in the database
    if redis_db.exists(mac_address):
        # Retrieve existing values
        existing_values = redis_db.hgetall(mac_address)
        existing_values_decoded = {k.decode('utf-8'): v.decode('utf-8') for k, v in existing_values.items()}
        
        # Compare existing values with new values
        if existing_values_decoded != values:
            print(f"redis MAC address {mac_address} exists and has different values")
            return False
        else:
            print(f"redis MAC address {mac_address} exists and already has the same values")
            ## Endpoint is up to date in Redis DB
            return True
    else:
        # Update the record if MAC address does not exist
        redis_db.hset(mac_address, mapping=values)
        print(f"redis MAC address {mac_address} added to the database with values")
        return False

def print_all_endpoints(redis_db):
    # Retrieve and print all MAC addresses and their values in the database
    keys = redis_db.keys('*')  # Get all keys in the database
    print("All endpoints in the Redis DB:")
    for key in keys:
        key_str = key.decode('utf-8')
        if redis_db.type(key) == b'hash':  # Ensure the key is a hash
            values = redis_db.hgetall(key_str)
            values_decoded = {k.decode('utf-8'): v.decode('utf-8') for k, v in values.items()}
            print(f"MAC Address: {key_str}, Values: {values_decoded}")

def clear_redis_db(redis_db):
    # Clear all entries in the Redis database
    redis_db.flushdb()
    print("All entries in the Redis DB have been cleared.")

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
                # print(f'proccessing packet # {currentPacket} - {packet.highest_layer}')
                process_packet(packet, packet.highest_layer)
            except TypeError as e:
                print(f'Error processing packet: {capture_file}, packet # {currentPacket}: TypeError: {e}')
                # logger.debug(f'Error processing packet: {capture_file}, packet # {currentPacket}: TypeError: {e}')
            currentPacket += 1
        capture.close()
        # end_time = time.perf_counter()
        # logger.debug(f'processing capture file complete: execution time: {end_time - start_time:0.6f} : {currentPacket} packets processed ##')
    # else:
    #     logger.debug(f'capture file not found: {capture_file}')

def capture_live_packets(network_interface, bpf_filter):
    global capture_count, skipped_packet
    currentPacket = 0
    capture = pyshark.LiveCapture(interface=network_interface, bpf_filter=bpf_filter, include_raw=True, use_json=True, output_file='/tmp/pyshark.pcapng')
    # logger.debug(f'beginning capture instance to file: {capture._output_file}')
    for packet in capture.sniff_continuously(packet_count=20000):
        try:
            highest_layer = packet.highest_layer
            if highest_layer not in ['DATA_RAW', 'TCP_RAW', 'UDP_RAW', 'JSON_RAW', 'DATA-TEXT-LINES_RAW', 'IMAGE-GIF_RAW', 'IMAGE-JFIF_RAW', 'PNG-RAW']:
                process_packet(packet, highest_layer)
            else:
                skipped_packet += 1
            currentPacket += 1
        except Exception as e:
            print(f'error processing packet {e}')
            # logger.warning(f'error processing packet {e}')
    capture.close()
    # logger.debug(f'stopping capture instance')
    ## Check for any orphaned 'dumpcap' processes from pyshark still running from old instance, and terminate them
    time.sleep(1)
    # proc_cleanup('dumpcap')
    capture_count += 1

if __name__ == '__main__':
    ## Parse input from initial start
    argparser = argparse.ArgumentParser(description="Provide ISE URL and API credentials.")
    argparser.add_argument('-u', '--username', required=True, help='The username')
    argparser.add_argument('-p', '--password', required=True, help='The password')
    argparser.add_argument('-a', '--url', required=True, help='The URL')
    argparser.add_argument('-i', '--interface', required=True, help='The network interface')
    args = argparser.parse_args()
    ints = netifaces.interfaces()
    if args.interface not in ints:
        print(f'Invalid interface name provided: {args.interface}.')
        print(f'Valid interface names are: {ints}')
        sys.exit(1)

    username = args.username
    password = args.password
    fqdn = 'https://' + args.url
    
    ## Validate that defined ISE instance has Custom Attributes defined
    print('### CHECKING ISE ATTRIBUTES ###')
    start_time = time.time()
    current_attribs = get_ise_attributes()
    validate_attributes(current_attribs, variables)
    end_time = time.time()
    print(f'Time taken: {end_time - start_time} seconds')

    print('### CREATING ENDPOINT SQLDB and REDIS DB ###')
    start_time = time.time()
    endpoints = endpointsdb()
    endpoints.create_database()
    redis_client = connect_to_redis()
    clear_redis_db(redis_client)
    end_time = time.time()
    print(f'Time taken: {end_time - start_time} seconds')
    
    # ### PCAP PARSING SECTION
    # print('### LOADING PCAP ###')
    # start_time = time.time()
    # process_capture_file(capture_file, default_filter)
    # end_time = time.time()
    # print(f'Time taken: {end_time - start_time} seconds')
    # update_ise_endpoints(endpoints, redis_client)
    # endpoints.view_all_entries()

    ### =========== LIVE CAPTURE TESTING =============== ###
    async def default_update_loop():
        try:
            count = 0
            while True:
                await asyncio.sleep(5.0)
                await update_ise_endpoints_async(endpoints, redis_client)
                # results = await endpoints.get_active_entries_async()
                # print(f'local db records pending update to ISE: {len(results)}')
                # if results:
                #     for row in results:
                #         print(f'record to update: {row}')
        except asyncio.CancelledError as e:
            pass
        print(f'shutting down loop instance')

    ## Setup the publishing loop
    main_task = asyncio.ensure_future(
        default_update_loop()
        )

    ## Setup sigint/sigterm handlers
    def signal_handlers():
        global capture_running
        main_task.cancel()
        # reregister_task.cancel()
        capture_running = False
    loop = asyncio.get_event_loop()
    loop.add_signal_handler(SIGINT, signal_handlers)
    loop.add_signal_handler(SIGTERM, signal_handlers)

    ## LIVE PCAP SECTION
    capture_running = True
    try:
        while capture_running:
            try:
                capture_live_packets(args.interface, default_bpf_filter)
            except Exception as e:
                print(f'error with catpure instance {e}')
    except KeyboardInterrupt:
        print(f'closing capture down due to keyboard interrupt')
        capture_running = False
        sys.exit(0)
    try:
        loop.run_until_complete(main_task)
    except:
        pass
    print(f'### LIVE PACKET CAPTURE STOPPED ##')
    # ### END LIVE CAPTURE TESTING

    ## REDIS OUTPUT
    print(f'number of redis entries: {redis_client.dbsize()}')
    # print_all_endpoints(redis_client)
    clear_redis_db(redis_client)
