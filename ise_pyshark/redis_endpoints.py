import redis
import logging
import time
import asyncio
from datetime import datetime
from ise_pyshark import apis

logger = logging.getLogger(__name__)

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

class redis_endpoints:
    def __init__(self,):
        start_time = time.time()
        logger.warning(f'redis DB creation - Start')
        # Use db=0 for local data
        self.local_db = redis.Redis(host='localhost', port=6379, db=0)
        # Use db=1 for remote data
        self.remote_db = redis.Redis(host='localhost', port=6379, db=1)

        self.local_db.flushdb()
        self.remote_db.flushdb()
        # print(f'local entries: {local_db.dbsize()}, remote entries: {remote_db.dbsize()}')
        self.local_db.hset(f"endpoint:{mac_address}", mapping=local_example_data)
        self.remote_db.hset(f"endpoint:{mac_address}", mapping=remote_example_data)
        # print(f'after template, local entries: {local_db.dbsize()}, remote entries: {remote_db.dbsize()}')
        end_time = time.time()
        logger.warning(f'redis DB creation - Completed: {round(end_time - start_time,4)}sec')

    def add_or_update_entry(self, redis_db, data_array, ise_sync=False):
        # Map array values to field names
        fields = [
            'mac', 'protocols', 'ip', 'id', 'name', 'vendor', 'hw', 'sw', 
            'productID', 'serial', 'device_type', 'id_weight', 'name_weight', 
            'vendor_weight', 'hw_weight', 'sw_weight', 'productID_weight', 
            'serial_weight', 'device_type_weight'
        ]
        # Identify Redis database (local or remote)
        redis_id = redis_db.connection_pool.connection_kwargs.get('db', 0)
        if redis_id == 0:       ## If referring to the parser's local redis db
            new_entry = {fields[i]: str(data_array[i]) for i in range(len(fields))}
        elif redis_id == 1:     ## If utilizing the remote cache db
            new_entry = {field: str(data_array.get(field, '')) for field in fields}

        # ## If this upadte includes current data from ISE
        # if ise_sync == True:
        #     new_entry['synced_to_ise'] = 'True'

        # Add dynamically generated timestamp
        new_entry['timestamp'] = datetime.now().isoformat()
        mac = new_entry['mac']
        existing_data = redis_db.hgetall(f"endpoint:{mac}")

        # Convert existing data from bytes to string if it exists
        if existing_data:
            existing_data = {k.decode('utf-8'): v.decode('utf-8') for k, v in existing_data.items()}
            
            # Check weight fields to decide whether to update
            weight_fields = ['id_weight', 'name_weight', 'vendor_weight', 'hw_weight', 'sw_weight', 
                            'productID_weight', 'serial_weight', 'device_type_weight']
            updated = False
            
            for field in weight_fields:
                new_weight = int(new_entry[field])
                exist_weight = int(existing_data.get(field, 0))
                corresponding_field = field.replace('_weight', '')

                if new_weight > exist_weight:
                    # Update both the weight and the corresponding field value
                    existing_data[field] = new_entry[field]
                    existing_data[corresponding_field] = new_entry[corresponding_field]
                    updated = True
            ## If existing data does not have same protocol list, check for individual protocols and append any new entries
            if new_entry['protocols'] != existing_data['protocols']:
                new_protos = set(new_entry['protocols'].split(','))
                existing_protos = set(existing_data['protocols'].split(','))
                for proto in new_protos:
                    if proto not in existing_protos:
                        existing_data['protocols'] = existing_data['protocols'] + ',' + proto
                        updated = True

            if updated:
                # Update the 'synced_to_ise' field if we're updating the record
                existing_data['synced_to_ise'] = 'False'
                logger.debug(f'Record for MAC {mac} updated.')
            else:
                # Update only the timestamp if weights are not higher to show data is still valid as of new time
                existing_data['timestamp'] = new_entry['timestamp']
                logger.debug(f"Record for MAC {mac} not updated; weights not higher.")
                return
        else:
            # If no existing data, create a new entry
            existing_data = new_entry
            existing_data['synced_to_ise'] = 'False'
            logger.debug(f'Record for MAC {mac} added to database')

        # Add or update the record in the local database
        redis_db.hset(f"endpoint:{mac}", mapping=existing_data)
        redis_db.sadd("endpoints:macs", mac)
        # logger.debug(f"Record for MAC {mac} added or updated.")

    async def update_ise_endpoints_async(self):
        try:
            logger.info(f'gather active endpoints - Start')
            start_time = time.time()
            ## Gather a copy of all of the local_redis entries that have new information
            results = await self.updated_local_entries_async()
            logger.debug(f'number of local || remote redis entries: {self.local_db.dbsize()} || {self.remote_db.dbsize()}')
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
                    status = await self.check_redis_remote_cache_async(self, row['mac'],attributes)
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
                                        if new_protos != ise_protos:
                                            protos = list(set(ise_custom_attrib['isepyProtocols'].split(',')) | set(attributes['isepyProtocols'].split(',')))
                                            attributes['isepyProtocols'] = ', '.join(map(str,protos))
                                            new_data = True
                                    ## For other fields, if newer data different, but certainty is same, update endpoint
                                    elif attributes[key] != ise_custom_attrib[key]:
                                        logger.debug(f"mac: {row['mac']} new value for {key} - old: {ise_custom_attrib[key]} | new: {attributes[key]}")
                                        new_data = True

                            ## Check if the existing ISE fields match the new attribute values
                            if attributes['isepyCertainty'] != ise_custom_attrib['isepyCertainty']:
                                logger.debug(f"different values for {row['mac']}")
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
                        self.add_or_update_redis_entry('1',row)

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

    def check_remote_cache(self, redis_db, mac_address, values):
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

    async def check_remote_cache_async(self, redis_db, mac_address, values):
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

    def updated_local_entries(self, local_redis):
        # Retrieve all MAC addresses stored in the local database
        mac_addresses = local_redis.smembers("endpoints:macs")
        updated_records = []

        for mac in mac_addresses:
            # Decode MAC address from bytes to string
            mac_str = mac.decode('utf-8')
            
            # Retrieve the hash for each MAC address
            entry = local_redis.hgetall(f"endpoint:{mac_str}")
            entry = {k.decode('utf-8'): v.decode('utf-8') for k, v in entry.items()}

            # Check if the 'synced_to_ise' field is set to 'False'
            if entry.get('synced_to_ise') == 'False':
                updated_records.append(entry)

        return updated_records

    async def updated_local_entries_async(self, local_redis):
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
            if entry.get('synced_to_ise') == 'False':
                updated_records.append(entry)

        return updated_records

    def print_endpoints(self,redis_db):
            # Define the key pattern or specific keys you want to fetch
            key_pattern = '*:*'  # Adjust this pattern based on your data

            # Retrieve keys matching the pattern
            keys = redis_db.keys(key_pattern)

            # Define the column names
            column_names = [
                'mac', 'protocols', 'ip', 'id', 'name', 'vendor', 'hw', 'sw',
                'productID', 'serial', 'device_type', 'id_weight', 'name_weight',
                'vendor_weight', 'hw_weight', 'sw_weight', 'productID_weight',
                'serial_weight', 'device_type_weight', 'timestamp', 'synced_to_ise'
            ]

            # Print the column names
            print('|'.join(column_names))

            # Iterate through each key and fetch its data
            i = 0
            while i < len(keys) - 1:
                key = keys[i]

                try:
                    # Check if the key is of type 'hash'
                    if redis_db.type(key).decode('utf-8') == 'hash':
                        entry = redis_db.hgetall(key)
                        row = [entry.get(col.encode(), b'').decode() for col in column_names]
                        print('|'.join(row))
                    else:
                        print(f"Skipping key {key.decode('utf-8')} - not a hash type.")
                except redis.exceptions.ResponseError as e:
                    print(f"Error processing key {key.decode('utf-8')}: {e}")
                i += 1
