import time
import pyshark
import redis
import asyncio
import argparse
import ipaddress
import sys
import os
import psutil
import logging
from signal import SIGINT, SIGTERM
from ise_pyshark import parser
from ise_pyshark import apis
from ise_pyshark import eps

logger = logging.getLogger(__name__)
headers = {'accept':'application/json','Content-Type':'application/json'}
default_bpf_filter = "(ip proto 0x2f || tcp port 80 || tcp port 8080 || udp port 1900 || udp port 138 || udp port 5060 || udp port 5353) and not ip6"
capture_running = False

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

async def update_ise_endpoints_async(local_redis, remote_redis):
    try:
        logger.info(f'gather active endpoints - Start')
        start_time = time.time()
        ## Gather a copy of all of the local_redis entries that have new information
        results = await redis_eps.updated_local_entries_async(local_redis)
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
                status = await redis_eps.check_remote_cache_async(remote_redis, row['mac'], attributes)
                ## If the value does not exist in remote redis cache, check returned API information against captured values
                if status == False:
                    ise_custom_attrib = await ise_apis.get_ise_endpoint_async(row['mac'])
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

                    redis_eps.add_or_update_entry(remote_redis,row, True)
            logger.info(f'check for endpoint updates to ISE - Start')
            if (len(endpoint_creates) + len(endpoint_updates)) == 0:
                logger.debug(f'no endpoints created or updated in ISE')
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
            end_time = time.time()
            logger.debug(f'check for endpoint updates to ISE - Completed {round(end_time - start_time,4)}sec')
        logger.info(f'gather active endpoints - Completed - {len(results)} records checked')
    except asyncio.CancelledError as e:
        logging.warning('routine check task cancelled')
        logging.warning(f'asyncio error - {e}')
        raise
    except Exception as e:
        logging.warning(f'an error occured during routine check: {e}')

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
                    redis_eps.add_or_update_entry(local_db,fn)
            else:
                for layer in packet.layers:
                    fn = packet_callbacks.get(layer.layer_name)
                    if fn is not None:
                        redis_eps.add_or_update_entry(local_db,fn(packet))
    except Exception as e:
        logger.debug(f'error processing packet details {highest_layer}: {e}')

def capture_live_packets(network_interface, bpf_filter):
    currentPacket = 0
    skipped_packet = 0
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

async def default_update_loop():
    try:
        while True:
            ## Every five minutes perform an update to ISE of any new information
            await asyncio.sleep(5.0)
            await update_ise_endpoints_async(local_db, remote_db)
    except asyncio.CancelledError as e:
        pass
    logger.debug(f'shutting down loop instance')

if __name__ == '__main__':
    ## Parse input from initial start
    argparser = argparse.ArgumentParser(description="Provide ISE URL and API credentials.")
    argparser.add_argument('-u', '--username', required=True, help='ISE API username')
    argparser.add_argument('-p', '--password', required=True, help='ISE API password')
    argparser.add_argument('-a', '--ip', required=True, help='ISE URL')
    argparser.add_argument('-i', '--interface', required=True, help='Network interface to monitor traffic')
    argparser.add_argument('-D', '--debug',  required=False, action='store_true', help='Enable debug logging')
    args = argparser.parse_args()

    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter('%(asctime)s:%(name)s:%(levelname)s:%(message)s'))
    logger.addHandler(handler)

    for modname in ['ise_pyshark.parser', 'ise_pyshark.eps', 'ise_pyshark.ouidb', 'ise_pyshark.apis']:
        s_logger = logging.getLogger(modname)
        handler.setFormatter(logging.Formatter('%(asctime)s:%(name)s:%(levelname)s:%(message)s'))
        s_logger.addHandler(handler)
        if args.debug == False:
            logger.setLevel(logging.INFO)
            s_logger.setLevel(logging.INFO)
        else:
            logger.setLevel(logging.DEBUG)
            s_logger.setLevel(logging.DEBUG)

    username = args.username
    password = args.password
    ip = args.ip
    interface = args.interface

    ints = psutil.net_if_addrs().keys()
    if args.interface not in ints:
        logger.warning(f'Invalid interface name provided: {args.interface}.')
        logger.warning(f'Valid interface names are: {ints}')
        sys.exit(1)
    
    if is_valid_IP(ip) == False:
        logger.warning('Invalid IP address provided')
        sys.exit(1)
    else:
        fqdn = 'https://'+ip

    ## Validate that defined ISE instance has Custom Attributes defined
    logger.warning(f'checking ISE custom attributes - Start')
    start_time = time.time()
    ise_apis = apis(fqdn, username, password, headers)
    current_attribs = ise_apis.get_ise_attributes()
    ise_apis.validate_attributes(current_attribs, variables)
    end_time = time.time()
    logger.warning(f'existing ISE attribute verification - Completed: {round(end_time - start_time,4)}sec')

    logger.warning(f'redis DB creation - Start')
    redis_eps = eps()
    # Use db=0 for local data
    local_db = redis.Redis(host='localhost', port=6379, db=0)
    # Use db=1 for remote data
    remote_db = redis.Redis(host='localhost', port=6379, db=1)

    local_db.flushdb()
    remote_db.flushdb()
    logger.warning(f'redis DB creation - Completed')

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

    logger.debug(f'local entries: {local_db.dbsize()}, remote entries: {remote_db.dbsize()}')
    print(f'LOCAL ENTRIES')
    redis_eps.print_endpoints(local_db)
    # print(f'REMOTE ENTRIES')
    # redis_eps.print_endpoints(remote_db)
    local_db.flushdb()
    remote_db.flushdb()
    logger.info(f'redis DB cache cleared')