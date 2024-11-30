import time
import pyshark
import redis
import asyncio
import argparse
import netifaces
import sys
import os
import psutil
import logging
from datetime import datetime
from signal import SIGINT, SIGTERM
from pathlib import Path
from ise_pyshark import parser
from ise_pyshark import apis
from ise_pyshark import endpointsdb

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

async def check_redis_remote_cache_async(redis_db, mac_address, values):
    existing_values = redis_db.hgetall(f"endpoint:{mac_address}")
    
    # Define the fields to check
    fields = [
        'mac', 'protocols', 'ip', 'id', 'name', 'vendor', 'hw', 'sw', 
        'productID', 'serial', 'device_type', 'id_weight', 'name_weight', 
        'vendor_weight', 'hw_weight', 'sw_weight', 'productID_weight', 
        'serial_weight', 'device_type_weight'
    ]

    # Check if MAC address exists in the database
    if existing_values:
        # Decode the existing values from bytes to strings
        existing_values_decoded = {k.decode('utf-8'): v.decode('utf-8') for k, v in existing_values.items()}

        # Filter existing values to only include the specified fields
        existing_filtered = {field: existing_values_decoded.get(field, '') for field in fields}

        certainties = values.get('isepyCertainty', '').split(',')

        # Create new_filtered by mapping values from 'values' dictionary to 'fields'
        new_filtered = {
            'mac':mac_address,
            'protocols': values.get('isepyProtocols', ''),
            'ip': values.get('isepyIP', ''),
            'id':'',
            'name': (values.get('isepyHostname', "")).replace("'","’"),
            'vendor': values.get('isepyVendor', ''),
            'hw': values.get('isepyModel', ''),
            'sw': values.get('isepyOS', ''),
            'productID': values.get('isepyDeviceID', ''),
            'serial': values.get('isepySerial', ''),
            'device_type': values.get('isepyType', ''),
            'id_weight':'0',
            'name_weight':certainties[0],
            'vendor_weight':certainties[1],
            'hw_weight':certainties[2],
            'sw_weight':certainties[3],
            'productID_weight':certainties[4],
            'serial_weight':certainties[5],
            'device_type_weight':certainties[6]
        }

        # Compare the filtered existing values with new values
        if existing_filtered != new_filtered:
            logger.debug(f"redis remote cache MAC address {mac_address} exists and has different values")
            logger.debug(f'{mac_address} existing: {existing_filtered} - new values: {new_filtered}')
            return False
        else:
            logger.debug(f"redis remote cache MAC address {mac_address} exists and already has the same values")
            return True
    else:
        logger.debug(f"no entry exists in redis remote cache for MAC address {mac_address}")
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

async def update_ise_endpoints_async(local_redis, remote_redis):
    try:
        logger.debug(f'gather active endpoints - Start')
        start_time = time.time()
        ## Gather a copy of all of the local_redis entries that have new information
        results = await updated_local_entries_async(local_redis)
        logger.debug(f'number of local || remote redis entries: {local_redis.dbsize()} || {remote_redis.dbsize()}')
        if results:
            endpoint_updates = []
            endpoint_creates = []
            for row in results:
                ## TODO - remove references to id, id_weight in endpointsdb
                ## Does not include row[3] for "id", nor row[11] for "id_weight"
                attributes = {
                        "isepyHostname": row['name'].replace("’","'"),
                        "isepyVendor": row['vendor'],
                        "isepyModel": row['hw'],
                        "isepyOS": row['sw'],
                        "isepyDeviceID": row['productID'],
                        "isepySerial": row['serial'],
                        "isepyType": row['device_type'],
                        "isepyProtocols": row['protocols'],
                        "isepyIP": row['ip'],
                        "isepyCertainty" : str(row['name_weight'])+","+str(row['vendor_weight'])+","+str(row['hw_weight'])+","+str(row['sw_weight'])+","+str(row['productID_weight'])+","+str(row['serial_weight'])+","+str(row['device_type_weight'])
                        }
                
                ## For every entry, check if remote_redis DB has record before sending API call to ISE
                status = await check_redis_remote_cache_async(remote_redis,row['mac'],attributes)
                ## If the value does not exist in remote redis cache, check returned API information against captured values
                if status == False:
                    iseCustomAttrib = await ise_apis.get_ise_endpoint_async(row['mac'])
                    if iseCustomAttrib == "no_values":
                        ## If endpoint exists, but custom attributes not populated, add to update queue
                        update = { "customAttributes": attributes, "mac": row['mac'] }
                        endpoint_updates.append(update)
                    elif iseCustomAttrib is None:
                        ## If endpoint does not exist, add to create queue
                        update = { "customAttributes": attributes, "mac": row['mac'] }
                        endpoint_creates.append(update)
                    else:                  
                        ## If endpoint already created and has isepy CustomAttributes populated
                        new_data = False
                        oldCertainty = iseCustomAttrib['isepyCertainty'].split(',')
                        newCertainty = attributes['isepyCertainty'].split(',')
                        if len(oldCertainty) != len(newCertainty):
                            logger.debug(f"Certainty values are of different lengths for {row['mac']}. Cannot compare.")
                        
                        ## If certainty score is weighted the same, check individual values for update
                        if attributes['isepyCertainty'] == iseCustomAttrib['isepyCertainty']:
                            logger.debug(f"mac: {row['mac']} - certainty values are the same - checking individual values")
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
                                    logger.debug(f"mac: {row['mac']} new value for {key} - old: {iseCustomAttrib[key]} | new: {attributes[key]}")
                                    new_data = True

                        ## Check if the existing ISE fields match the new attribute values
                        if attributes['isepyCertainty'] != iseCustomAttrib['isepyCertainty']:
                            logger.debug(f"different values for {row['mac']}")
                            # Compare element-wise
                            for i in range(len(oldCertainty)):
                                # Convert strings to integers
                                value1 = int(oldCertainty[i])
                                value2 = int(newCertainty[i])
                                if value2 > value1:
                                    new_data = True
                        ## If the local redis values have newer data for the endpoint, add to ISE update queue
                        if new_data == True:
                            update = { "customAttributes": attributes, "mac": row['mac'] } 
                            endpoint_updates.append((update))
                        else:
                            logger.debug(f"no new data for endoint: {row['mac']}")
                    add_or_update_redis_entry(remote_redis,row)

            logger.debug(f'check for endpoint updates to ISE - Start')
            if len(endpoint_updates) > 0:
                logger.debug(f'creating, updating {len(endpoint_updates)} endpoints in ISE - Start')
                chunk_size = 500
                for i in range(0, len(endpoint_updates),chunk_size):
                    chunk = endpoint_updates[i:i + chunk_size]
                    ## TODO perform similar try/except blocks with timeouts for other API and async-based functions
                    try:
                        result = await asyncio.wait_for(ise_apis.bulk_update_put_async(chunk), timeout=3)
                    except asyncio.TimeoutError:
                        logger.warning('API call to ISE for endpoint update timed out')
                logger.debug(f'updating {len(endpoint_updates)} endpoints in ISE - Completed')
            if len(endpoint_creates) > 0:
                logger.debug(f'creating {len(endpoint_creates)} new endpoints in ISE - Start')
                chunk_size = 500
                for i in range(0, len(endpoint_creates),chunk_size):
                    chunk = endpoint_creates[i:i + chunk_size]
                    try: 
                        result = await asyncio.wait_for(ise_apis.bulk_update_post_async(chunk), timeout=3)
                    except asyncio.TimeoutError:
                        logger.warning('API call to ISE for endpoint creation timed out')
                logger.debug(f'creating {len(endpoint_creates)} new endpoints in ISE - Completed')
            if (len(endpoint_creates) + len(endpoint_updates)) == 0:
                logger.debug(f'no endpoints created or updated in ISE')
            end_time = time.time()
            logger.debug(f'check for endpoint updates to ISE - Completed {round(end_time - start_time,4)}sec')
        logger.debug(f'gather active endpoints - Completed')
    except asyncio.CancelledError:
        logging.warning('routine check task cancelled')
        raise
    except Exception as e:
        logging.warning(f'an error occured during routine check: {e}')

## Check all local entries for "up_to_date"
async def updated_local_entries_async(local_redis):
    # Retrieve all MAC addresses stored in the local database
    mac_addresses = local_redis.smembers("endpoints:macs")
    updated_records = []

    for mac in mac_addresses:
        # Decode MAC address from bytes to string
        mac_str = mac.decode('utf-8')
        
        # Retrieve the hash for each MAC address
        entry = local_redis.hgetall(f"endpoint:{mac_str}")
        entry = {k.decode('utf-8'): v.decode('utf-8') for k, v in entry.items()}

        # Check if the 'updated' field is set to 'True'
        if entry.get('up_to_date') == 'True':
            updated_records.append(entry)

    return updated_records

## Update the redis local cache DB based on parser data
def add_or_update_redis_entry(redis_db,data_array):
    # Map array values to field names
    fields = [
        'mac', 'protocols', 'ip', 'id', 'name', 'vendor', 'hw', 'sw', 
        'productID', 'serial', 'device_type', 'id_weight', 'name_weight', 
        'vendor_weight', 'hw_weight', 'sw_weight', 'productID_weight', 
        'serial_weight', 'device_type_weight'
    ]
    redis_id = redis_db.connection_pool.connection_kwargs.get('db', 0)
    if redis_id == 0:       ## If referring to the parser's local redis db
        new_entry = {fields[i]: str(data_array[i]) for i in range(len(fields))}
    elif redis_id == 1:     ## If utilizing the remote cache db
        new_entry = {field: str(data_array.get(field, '')) for field in fields}
    # print(f'new entry db={redis_id} = {new_entry}')

    # Add dynamically generated timestamp
    new_entry['timestamp'] = datetime.now().isoformat()
    # Default 'updated' to False initially
    new_entry['up_to_date'] = 'False'

    mac = new_entry['mac']
    existing_data = redis_db.hgetall(f"endpoint:{mac}")

    # Convert existing data from bytes to string if it exists
    if existing_data:
        existing_data = {k.decode('utf-8'): v.decode('utf-8') for k, v in existing_data.items()}

        # Check weight fields to decide whether to update
        weight_fields = ['id_weight', 'name_weight', 'vendor_weight', 'hw_weight', 'sw_weight', 
                         'productID_weight', 'serial_weight', 'device_type_weight']
        
        can_update = all(
            int(new_entry[field]) >= int(existing_data.get(field, '0')) for field in weight_fields
        )

        if not can_update:
            logger.debug(f"record for MAC {mac} not updated due to lower weight values.")
            return

    # Update the 'updated' field if we're updating the record
    new_entry['up_to_date'] = 'True'

    # Add or update the record in the local database
    redis_db.hset(f"endpoint:{mac}", mapping=new_entry)
    redis_db.sadd("endpoints:macs", mac)
    logger.debug(f"record for MAC {mac} added or updated.")

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
                    # endpoints.update_db_list(fn)
                    add_or_update_redis_entry(local_db,fn)
            else:
                for layer in packet.layers:
                    fn = packet_callbacks.get(layer.layer_name)
                    if fn is not None:
                        # endpoints.update_db_list(fn(packet))
                        add_or_update_redis_entry(local_db,fn(packet))
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
            await asyncio.sleep(30.0)
            await update_ise_endpoints_async(local_db, remote_db)
    except asyncio.CancelledError as e:
        pass
    logger.debug(f'shutting down loop instance')

if __name__ == '__main__':
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter('%(asctime)s:%(name)s:%(levelname)s:%(message)s'))
    logger.addHandler(handler)
    logger.setLevel(logging.DEBUG)

    for modname in ['ise_pyshark.parser', 'ise_pyshark.endpointsdb', 'ise_pyshark.ouidb', 'ise_pyshark.apis']:
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
    ise_apis = apis(fqdn, username, password, headers)
    current_attribs = ise_apis.get_ise_attributes()
    ise_apis.validate_attributes(current_attribs, variables)
    end_time = time.time()
    logger.warning(f'existing ISE attribute verification - Completed: {round(end_time - start_time,4)}sec')

    logger.warning(f'SQLDB and Redis DB creation - Start')
    start_time = time.time()
    endpoints = endpointsdb()
    endpoints.create_database()

    mac_address = '00:11:22:33:44:55'
    # Example data for the local database
    local_example_data = {
        'mac': mac_address,
        'protocols': 'TCP',
        'ip': '192.168.1.1',
        'id': 'device123',
        'name': 'LocalDevice',
        'vendor': 'LocalVendor',
        'hw': 'HW1',
        'sw': 'SW1',
        'productID': 'ProductLocal',
        'serial': 'SerialLocal',
        'device_type': 'Router',
        'id_weight': '1',
        'name_weight': '1',
        'vendor_weight': '1',
        'hw_weight': '1',
        'sw_weight': '1',
        'productID_weight': '1',
        'serial_weight': '1',
        'device_type_weight': '1',
        'timestamp': '2023-10-05T14:48:00',
        'up_to_date': 'True'
    }
    # Example data for the remote database
    remote_example_data = {
        'mac': mac_address,
        'protocols': 'TCP',
        'ip': '192.168.1.2',
        'id': 'device123',
        'name': 'RemoteDevice',
        'vendor': 'RemoteVendor',
        'hw': 'HW1',
        'sw': 'SW2',
        'productID': 'ProductRemote',
        'serial': 'SerialRemote',
        'device_type': 'Router',
        'id_weight': '1',
        'name_weight': '1',
        'vendor_weight': '1',
        'hw_weight': '1',
        'sw_weight': '1',
        'productID_weight': '1',
        'serial_weight': '1',
        'device_type_weight': '1',
        'timestamp': '2023-10-05T14:49:00',
        'up_to_date': 'False'
    }
    
    logger.warning(f'redis DB creation - Start')
    # Use db=0 for local data
    local_db = redis.Redis(host='localhost', port=6379, db=0)
    # Use db=1 for remote data
    remote_db = redis.Redis(host='localhost', port=6379, db=1)

    local_db.flushdb()
    remote_db.flushdb()
    # print(f'local entries: {local_db.dbsize()}, remote entries: {remote_db.dbsize()}')
    local_db.hset(f"endpoint:{mac_address}", mapping=local_example_data)
    remote_db.hset(f"endpoint:{mac_address}", mapping=remote_example_data)
    # print(f'after template, local entries: {local_db.dbsize()}, remote entries: {remote_db.dbsize()}')
    end_time = time.time()
    logger.warning(f'redis DB creation - Completed: {round(end_time - start_time,4)}sec')

    ## Setup the publishing loop
    main_task = asyncio.ensure_future(
        default_update_loop()
        )

    ## Setup sigint/sigterm handlers
    def signal_handlers():
        global capture_running
        main_task.cancel()
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
    # logger.debug(f'number of redis entries: {local_db.dbsize()}')
    logger.debug(f'local entries: {local_db.dbsize()}, remote entries: {remote_db.dbsize()}')
    print(f'LOCAL ENTRIES')
    print_all_endpoints(local_db)
    print(f'REMOTE ENTRIES')
    print_all_endpoints(remote_db)
    local_db.flushdb()
    remote_db.flushdb()
    logger.debug(f'redis DB cache cleared')