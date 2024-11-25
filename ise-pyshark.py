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
capture_file = 'captures/simulation.pcapng'
default_filter = '!ipv6 && (ssdp || (http && http.user_agent != "") || xml || browser || (mdns && (dns.resp.type == 1 || dns.resp.type == 16)))'
default_bpf_filter = "(ip proto 0x2f || tcp port 80 || tcp port 8080 || udp port 1900 || udp port 138 || udp port 5060 || udp port 5353) and not ip6"
capture_running = False
capture_count = 0
skipped_packet = 0

# mac_filter = 'eth.addr == BC:14:85:11:22:33'
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

async def get_ise_endpoint_async(mac):
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

async def bulk_update_put_async(update):
    url = f'{fqdn}/api/v1/endpoint/bulk'
    try:
        response = requests.put(url, headers=headers, json=update, auth=HTTPBasicAuth(username, password), verify=False)
        logger.debug(f'api response = {response.json()}')
    except requests.exceptions.RequestException as err:
        logger.warning(f'unable to update endponits within ISE - {err}')

async def bulk_update_post_async(update):
    url = f'{fqdn}/api/v1/endpoint/bulk'
    try:
        response = requests.post(url, headers=headers, json=update, auth=HTTPBasicAuth(username, password), verify=False)
        logger.debug(f'api response = {response.json()}')
    except requests.exceptions.RequestException as err:
        logger.warning(f'unable to update endponits within ISE - {err}')

## Check if the sql db has any updates and compare against redis cache
async def update_ise_endpoints_async(endpoints_db, redis_db):
    try:
        logger.debug(f'gather active endpoints - Start')
        start_time = time.time()
        ## Gather a copy of all of the sqldb entries that have new information
        results = await endpoints_db.get_active_entries_async()
        logger.debug(f'number of redis entries: {redis_db.dbsize()}')
        if results:
            endpoint_updates = []
            endpoint_creates = []
            for row in results:
                ## TODO - remove references to id, id_weight in endpointsdb
                ## Does not include row[3] for "id", nor row[11] for "id_weight"
                attributes = {
                        "isepyHostname": row[4].replace("’","'"),
                        "isepyVendor": row[5],
                        "isepyModel": row[6],
                        "isepyOS": row[7],
                        "isepyDeviceID": row[8],
                        "isepySerial": row[9],
                        "isepyType": row[10],
                        "isepyProtocols": row[1],
                        "isepyIP": row[2],
                        "isepyCertainty" : str(row[12])+","+str(row[13])+","+str(row[14])+","+str(row[15])+","+str(row[16])+","+str(row[17])+","+str(row[18])
                        }
                
                ## For every entry, check if Redis DB has record before sending API call to ISE
                status = await check_mac_redis_status_async(redis_db,row[0],attributes)
                if status == False:
                    iseCustomAttrib = await get_ise_endpoint_async(row[0])
                    if iseCustomAttrib == "no_values":
                        ## If endpoint exists, but custom attributes not populated, add to update queue
                        update = { "customAttributes": attributes, "mac": row[0] }
                        endpoint_updates.append(update)
                    elif iseCustomAttrib is None:
                        ## If endpoint does not exist, add to create queue
                        update = { "customAttributes": attributes, "mac": row[0] }
                        endpoint_creates.append(update)
                    else:                  
                        ## If endpoint already created and has isepy CustomAttributes populated
                        new_data = False
                        oldCertainty = iseCustomAttrib['isepyCertainty'].split(',')
                        newCertainty = attributes['isepyCertainty'].split(',')
                        if len(oldCertainty) != len(newCertainty):
                            logger.debug(f"Certainty values are of different lengths for {row[0]}. Cannot compare.")
                        
                        ## If certainty score is weighted the same, check individual values for update
                        if attributes['isepyCertainty'] == iseCustomAttrib['isepyCertainty']:
                            ## Iterate through data fields and check against ISE current values
                            for key in attributes:
                                ## If checking the protocols observed field...
                                if key == 'isepyProtocols':
                                    new_protos = set(attributes['isepyProtocols'].split(','))
                                    ise_protos = set(iseCustomAttrib['isepyProtocols'].split(','))
                                    ## Combine any new protocols with existing values
                                    if new_protos != ise_protos:
                                        protos = list(set(iseCustomAttrib['isepyProtocols'].split(',')) | set(attributes['isepyProtocols'].split(',')))
                                        attributes['isepyProtocols'] = ', '.join(map(str,protos))
                                        new_data = True
                                ## For other fields, if newer data different, but certainty is same, update endpoint
                                elif attributes[key] != iseCustomAttrib[key]:
                                    new_data = True

                        ## Check if the existing ISE fields match the new attribute values
                        if attributes['isepyCertainty'] != iseCustomAttrib['isepyCertainty']:
                            logger.debug(f'different values for {row[0]}')
                            print(f'old {iseCustomAttrib}')
                            print(f'new {attributes}')
                            # oldCertainty = iseCustomAttrib['isepyCertainty'].split(',')
                            # newCertainty = attributes['isepyCertainty'].split(',')

                            # Compare element-wise
                            for i in range(len(oldCertainty)):
                                # Convert strings to integers
                                value1 = int(oldCertainty[i])
                                value2 = int(newCertainty[i])
                                if value2 > value1:
                                    new_data = True
                        if new_data == True:
                            update = { "customAttributes": attributes, "mac": row[0] } 
                            endpoint_updates.append((update))
            
            logger.debug(f'check for endpoint updates to ISE - Start')
            if len(endpoint_updates) > 0:
                logger.debug(f'creating, updating {len(endpoint_updates)} endpoints in ISE - Start')
                chunk_size = 500
                for i in range(0, len(endpoint_updates),chunk_size):
                    chunk = endpoint_updates[i:i + chunk_size]
                    ## TODO perform similar try/except blocks with timeouts for other API and async-based functions
                    try:
                        result = await asyncio.wait_for(bulk_update_put_async(chunk), timeout=3)
                    except asyncio.TimeoutError:
                        logger.warning('API call to ISE for endpoint update timed out')
                logger.debug(f'updating {len(endpoint_updates)} endpoints in ISE - Completed')
            if len(endpoint_creates) > 0:
                logger.debug(f'creating {len(endpoint_creates)} new endpoints in ISE - Start')
                chunk_size = 500
                for i in range(0, len(endpoint_creates),chunk_size):
                    chunk = endpoint_creates[i:i + chunk_size]
                    try: 
                        result = await asyncio.wait_for(bulk_update_post_async(chunk), timeout=3)
                    except asyncio.TimeoutError:
                        logger.warning('API call to ISE for endpoint creation timed out')
                logger.debug(f'creating {len(endpoint_creates)} new endpoints in ISE - Completed')
            if (len(endpoint_creates) + len(endpoint_updates)) == 0:
                logger.debug(f'no endpoints created or updated in ISE')
            end_time = time.time()
            logger.debug(f'check for endpoint updates to ISE - Completed {round(end_time - start_time,4)}sec')
    except asyncio.CancelledError:
        logging.warning('routine check task cancelled')
        raise
    except Exception as e:
        logging.warning(f'an error occured during routine check: {e}')

### REDIS SECTION
def connect_to_redis():
    # Connect to Redis server
    r = redis.Redis(host='localhost', port=6379, db=0)
    return r

async def check_mac_redis_status_async(redis_db, mac_address, values):
    # Check if MAC address exists in the database
    if redis_db.exists(mac_address):
        # Retrieve existing values
        existing_values = redis_db.hgetall(mac_address)
        existing_values_decoded = {k.decode('utf-8'): v.decode('utf-8') for k, v in existing_values.items()}
        
        # Compare existing values with new values
        if existing_values_decoded != values:
            logger.debug(f"redis MAC address {mac_address} exists and has different values")
            logger.debug(f'{mac_address} existing: {existing_values_decoded} - new values: {values}')
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

## Return a list of processes matching 'name' (https://psutil.readthedocs.io/en/latest/)
def find_procs_by_name(name):
    ls = []
    for p in psutil.process_iter(['name']):
        # if p.info['name'] == name:
        if name in p.info['name']:
            ls.append(p )
    return ls

## Kill a process based on provided PID value (https://psutil.readthedocs.io/en/latest/)
def kill_proc_tree(pid, sig=SIGTERM, include_parent=True, timeout=None, on_terminate=None):
    assert pid != os.getpid(), "won't kill myself"
    parent = psutil.Process(pid)
    # logger.debug(f'parent: {parent}')
    children = parent.children(recursive=True)
    # logger.debug(f'child: {children}')
    if include_parent:
        children.append(parent)
    for p in children:
        try:
            p.send_signal(sig)
            # logger.debug(f'sending terminate signal')
        except psutil.NoSuchProcess:
            pass
    gone, alive = psutil.wait_procs(children, timeout=timeout,
                                    callback=on_terminate)
    return (gone, alive)

## Wrap the search and kill process functions into single call
def proc_cleanup(proc_name):
    proc_check = find_procs_by_name(proc_name)
    if len(proc_check) > 0:
        for item in proc_check:
            logger.warning(f'orphaned {item._name} proc: {item.pid}')
            proc_kill = kill_proc_tree(item.pid)
            if len(proc_kill) > 0:
                if f"{item.pid}, status='terminated'" in str(proc_kill):
                    logger.warning(f'orphaned proc {item.pid} terminated')

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

def capture_live_packets(network_interface, bpf_filter):
    global capture_count, skipped_packet
    currentPacket = 0
    capture = pyshark.LiveCapture(interface=network_interface, bpf_filter=bpf_filter, include_raw=True, use_json=True, output_file='/tmp/pyshark.pcapng')
    logger.debug(f'beginning capture instance to file: {capture._output_file}')
    for packet in capture.sniff_continuously(packet_count=200000):
        try:
            highest_layer = packet.highest_layer
            if highest_layer not in ['DATA_RAW', 'TCP_RAW', 'UDP_RAW', 'JSON_RAW', 'DATA-TEXT-LINES_RAW', 'IMAGE-GIF_RAW', 'IMAGE-JFIF_RAW', 'PNG-RAW']:
                process_packet(packet, highest_layer)
            else:
                skipped_packet += 1
            currentPacket += 1
        except Exception as e:
            logger.debug(f'error processing packet {e}')
            logger.warning(f'error processing packet {e}')
    logger.debug(f'captured packets = {currentPacket}, skipped packets = {skipped_packet}')
    capture.close()
    logger.debug(f'stopping capture instance')
    ## Check for any orphaned 'dumpcap' processes from pyshark still running from old instance, and terminate them
    time.sleep(1)
    # proc_cleanup('dumpcap')
    capture_count += 1

async def default_update_loop():
    try:
        while True:
            await asyncio.sleep(5.0)
            await update_ise_endpoints_async(endpoints, redis_client)
    except asyncio.CancelledError as e:
        pass
    logger.debug(f'shutting down loop instance')

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
    # argparser.add_argument('-i', '--interface', required=True, help='Network interface to monitor traffic')
    # argparser.add_argument('-D', '--debug', required=False, help='Enable debug logging')
    # args = argparser.parse_args()
    # ints = netifaces.interfaces()
    # if args.interface not in ints:
    #     logger.debug(f'Invalid interface name provided: {args.interface}.')
    #     logger.debug(f'Valid interface names are: {ints}')
    #     sys.exit(1)
    # username = args.username
    # password = args.password
    # fqdn = 'https://' + args.url
    # interface = args.interface

    username = 'api-admin'
    password = 'Password123'
    fqdn = 'https://10.0.1.90'
    interface = 'en0'
    
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
                # capture_live_packets(args.interface, default_bpf_filter)
                capture_live_packets(interface, default_bpf_filter)
            except Exception as e:
                logger.warning(f'error with catpure instance {e}')
    except KeyboardInterrupt:
        logger.warning(f'closing capture down due to keyboard interrupt')
        capture_running = False
        sys.exit(0)
    try:
        loop.run_until_complete(main_task)
    except:
        pass
    logger.warning(f'### LIVE PACKET CAPTURE STOPPED ###')

    ## REDIS OUTPUT
    logger.debug(f'number of redis entries: {redis_client.dbsize()}')
    clear_redis_db(redis_client)
