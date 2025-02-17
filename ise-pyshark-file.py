import time
import pyshark
import redis
import asyncio
import ipaddress
import logging
import sys
from pathlib import Path
from ise_pyshark import parser
from ise_pyshark import apis
from ise_pyshark import eps

logger = logging.getLogger(__name__)
headers = {'accept':'application/json','Content-Type':'application/json'}
default_filter = '!ipv6 && (ssdp || (http && http.user_agent != "") || xml || sip || browser || (mdns && (dns.resp.type == 1 || dns.resp.type == 16)))'
capture_running = False
capture_count = 0
skipped_packet = 0

# # mac_filter = 'eth.addr == 00:11:22:33:44:55'
# if mac_filter != '':
#     default_filter = mac_filter + ' && ' + default_filter
parser = parser()
packet_callbacks = {
    'mdns': parser.parse_mdns_v8,
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

## Confirm provided value is valid IP address
def is_valid_IP(address):
    try:
        # Attempt to create an IPv4 address object
        ipaddress.IPv4Address(address)
        return True
    except ipaddress.AddressValueError:
        return False

## Pull up the cache of local endpoints and then send updates to ISE
def update_ise_endpoints(local_redis, remote_redis):
    try:
        logger.info(f'gather active endpoints - Start')
        start_time = time.time()
        ## Gather a copy of all of the local_redis entries that have new information
        results = redis_eps.updated_local_entries(local_redis)
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
                status = redis_eps.check_remote_cache(remote_redis,row['mac'],attributes)
                ## If the value does not exist in remote redis cache, check returned API information against captured values
                if status == False:
                    ise_custom_attrib = ise_apis.get_ise_endpoint(row['mac'])
                    if ise_custom_attrib == "no_values":
                        ## If endpoint exists, but custom attributes not populated, add to update queue
                        update = { "customAttributes": attributes, "mac": row['mac'] }
                        endpoint_updates.append(update)
                    elif ise_custom_attrib is None:
                        ## If endpoint does not exist, add to create queue
                        update = { "customAttributes": attributes, "mac": row['mac'] }
                        endpoint_creates.append(update)
                    else:                  
                        ## If endpoint already created and has isepy CustomAttributes populated
                        new_data = False
                        old_certainty = ise_custom_attrib['isepyCertainty'].split(',')
                        new_certainty = attributes['isepyCertainty'].split(',')
                        if len(old_certainty) != len(new_certainty):
                            logger.debug(f"Certainty values are of different lengths for {row['mac']}. Cannot compare.")
                        
                        ## If certainty score is weighted the same, check individual values for update
                        if attributes['isepyCertainty'] == ise_custom_attrib['isepyCertainty']:
                            logger.debug(f"mac: {row['mac']} - certainty values are the same - checking individual values")
                            ## Iterate through data fields and check against ISE current values
                            for key in attributes:
                                ## If checking the protocols observed field...
                                if key == 'isepyProtocols':
                                    new_protos = set(attributes['isepyProtocols'].split(','))
                                    ise_protos = set(ise_custom_attrib['isepyProtocols'].split(','))
                                    ## Combine any new protocols with existing values
                                    if new_protos.issubset(ise_protos):
                                        new_data = False
                                    else:
                                        protos = list(set(ise_custom_attrib['isepyProtocols'].split(',')) | set(attributes['isepyProtocols'].split(',')))
                                        attributes['isepyProtocols'] = ','.join(map(str,protos))
                                        new_data = True
                                        break
                                ## For other fields, if newer data different, but certainty is same, update endpoint
                                elif attributes[key] != ise_custom_attrib[key]:
                                    logger.debug(f"mac: {row['mac']} new value for {key} - old: {ise_custom_attrib[key]} | new: {attributes[key]}")
                                    new_data = True
                                    break

                        ## Check if the existing ISE fields match the new attribute values
                        if attributes['isepyCertainty'] != ise_custom_attrib['isepyCertainty']:
                            logger.debug(f"different certainty values for {row['mac']}")
                            # Compare element-wise
                            for i in range(len(old_certainty)):
                                # Convert strings to integers
                                value1 = int(old_certainty[i])
                                value2 = int(new_certainty[i])
                                if value2 > value1:
                                    new_data = True
                        ## If the local redis values have newer data for the endpoint, add to ISE update queue
                        if new_data == True:
                            update = { "customAttributes": attributes, "mac": row['mac'] } 
                            endpoint_updates.append((update))
                        else:
                            logger.debug(f"no new data for endoint: {row['mac']}")
                    redis_eps.add_or_update_entry(remote_redis,row)

            logger.info(f'check for endpoint updates to ISE - Start')
            if (len(endpoint_creates) + len(endpoint_updates)) == 0:
                logger.debug(f'no endpoints created or updated in ISE')
            if len(endpoint_updates) > 0:
                logger.debug(f'creating, updating {len(endpoint_updates)} endpoints in ISE - Start')
                chunk_size = 500
                for i in range(0, len(endpoint_updates),chunk_size):
                    chunk = endpoint_updates[i:i + chunk_size]
                    ## TODO perform similar try/except blocks with timeouts for other API and async-based functions
                    result = ise_apis.bulk_update_put(chunk)
                logger.debug(f'updating {len(endpoint_updates)} endpoints in ISE - Completed')
            if len(endpoint_creates) > 0:
                logger.debug(f'creating {len(endpoint_creates)} new endpoints in ISE - Start')
                chunk_size = 500
                for i in range(0, len(endpoint_creates),chunk_size):
                    chunk = endpoint_creates[i:i + chunk_size]
                    result = ise_apis.bulk_update_post(chunk)
                logger.debug(f'creating {len(endpoint_creates)} new endpoints in ISE - Completed')
            end_time = time.time()
            logger.debug(f'check for endpoint updates to ISE - Completed {round(end_time - start_time,4)}sec')
        logger.info(f'gather active endpoints - Completed - {len(results)} records checked')
    except asyncio.CancelledError:
        logging.warning('routine check task cancelled')
        raise
    except Exception as e:
        logging.warning(f'an error occured during routine check: {e}')

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
                    redis_eps.add_or_update_entry(local_db,fn)
            else:
                for layer in packet.layers:
                    fn = packet_callbacks.get(layer.layer_name)
                    if fn is not None:
                        redis_eps.add_or_update_entry(local_db,fn(packet))
    except Exception as e:
        logger.debug(f'error processing packet details {highest_layer}: {e}')

## Process a given PCAP(NG) file with a provided PCAP filter
def process_capture_file(capture_file, capture_filter):
    if Path(capture_file).exists():
        logger.info(f'processing capture file: {capture_file}')
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
        logger.info(f'processing capture file complete: execution time: {end_time - start_time:0.6f} : {currentPacket} packets processed ##')
    else:
        logger.warning(f'capture file not found: {capture_file}')
        sys.exit(0)

if __name__ == '__main__':
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter('%(asctime)s:%(name)s:%(levelname)s:%(message)s'))
    logger.addHandler(handler)
    logger.setLevel(logging.DEBUG)
    for modname in ['ise_pyshark.parser', 'ise_pyshark.eps', 'ise_pyshark.ouidb', 'ise_pyshark.apis']:
        s_logger = logging.getLogger(modname)
        handler.setFormatter(logging.Formatter('%(asctime)s:%(name)s:%(levelname)s:%(message)s'))
        s_logger.addHandler(handler)
        s_logger.setLevel(logging.DEBUG)
    
    print('#######################################')
    print('##  ise-pyshark capture file')
    print('#######################################')
    filename = input('Input local pcap(ng) file to be parsed: ')
    filter = input('Input custom wireshark filter (leave blank to use built-in filter): ')
    if filter == '':
        filter = default_filter
    print('#######################################')
    print('##  Analyzing capture file')
    print('#######################################')

    logger.debug(f'redis DB creation - Start')
    redis_eps = eps()
    local_db = redis.Redis(host='localhost', port=6379, db=0)   # Use db=0 for local data
    remote_db = redis.Redis(host='localhost', port=6379, db=1)  # Use db=1 for remote data
    local_db.flushdb()
    remote_db.flushdb()
    logger.debug(f'redis DB creation - Completed')
    
    # ### PCAP PARSING SECTION
    start_time = time.time()
    process_capture_file(filename, default_filter)
    end_time = time.time()
    redis_eps.print_endpoints(local_db)
    print('#######################################')
    print('##  Capture File Analysis Complete')
    print(f'##  Time Taken: {round(end_time - start_time,4)}sec')
    print('#######################################')
    update_ise = input('Send above endpoint data from PCAP(NG) file to ISE [y/n]: ')
    if update_ise == 'y':
        ip = input('ISE Admin Node IP Address: ')
        if is_valid_IP(ip) == False:
            print('Invalid IP address provided')
            sys.exit(0)
        username = input('ISE API Admin Username: ')
        password = input('ISE API Admin Password: ')
    else:
        sys.exit(0)
    fqdn = 'https://'+ip

    # Validate that defined ISE instance has Custom Attributes defined
    logger.warning(f'checking ISE custom attributes - Start')
    start_time = time.time()
    ise_apis = apis(fqdn, username, password, headers)
    current_attribs = ise_apis.get_ise_attributes()
    ise_apis.validate_attributes(current_attribs, variables)
    end_time = time.time()
    logger.warning(f'existing ISE attribute verification - Completed: {round(end_time - start_time,4)}sec')
    update_ise_endpoints(local_db, remote_db)
    local_db.flushdb()
    remote_db.flushdb()
    logger.info(f'redis DB cache cleared')
    print('#######################################')
    print('## ISE Endpoint data updates completed ')
    print('#######################################')