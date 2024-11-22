import sqlite3
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

records_updated = 0
records_created = 0
ise_updates = 0

class endpointsdb:
    def __init__(self, db_file='endpoint_database.db'):
        self.connection = sqlite3.connect(db_file)
        self.cursor = self.connection.cursor()
        self.clear_database()

    def clear_database(self):
        self.cursor.execute('DROP TABLE IF EXISTS endpoints')
        logger.debug('clear endpooints DB - complete')

    ## Create table for holding endpoint data; remove table if already exists to avoid old data
    def create_database(self):
        logger.debug('create endpoints DB - starting')
        self.cursor.execute('DROP TABLE IF EXISTS endpoints')
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS endpoints (
                mac TEXT PRIMARY KEY, protocol TEXT, ip TEXT,
                id TEXT, name TEXT, vendor TEXT, hw TEXT, sw TEXT, productID TEXT, serial TEXT, device_type TEXT,
                id_weight INT DEFAULT 1, name_weight INT DEFAULT 1, vendor_weight INT DEFAULT 1, hw_weight INT DEFAULT 1, sw_weight INT DEFAULT 1, productID_weight INT DEFAULT 1, serial_weight INT DEFAULT 1, device_type_weight INT DEFAULT 1,
                timestamp TIME, updated BOOLEAN )
                            ''')
                ## mac=0, protocol=1, ip=2
                ## id=3, name=4, vendor=5, hw=6, sw=7, productid=8, serial=9, device_type=10
                ## id_w=11, name_w=12, vendor_w=13, hw_w=14, sw_w=15, product_w=16, serial_w=17, device_w=18,
                ## time=19, updated=20
        self.cursor.execute('CREATE INDEX IF NOT EXISTS idx_mac ON endpoints (mac)')
        self.connection.commit()
        logger.debug('create endpoints DB - complete')
    
    def update_db_list(self, values_list):
        global records_created, records_updated                 # Values of DB record updates for efficiency tracking
        mac = values_list[0]                                    
        self.cursor.execute('SELECT * FROM endpoints WHERE mac = ?', (mac,))
        existing_record = self.cursor.fetchone()                # Grab any matching entry based on MAC
        if existing_record:
            # print(f'existing record: {existing_record}')
            # print(f'new record: {values_list}')
            update_values = {}                                  # Temp array to hold any new values
            if not existing_record[1] and values_list[1]:
                update_values['protocol'] = values_list[1]
            elif existing_record[1] != values_list[1]:          # Append new protocol to existing protocol string in DB
                if str(values_list[1]) not in str(existing_record[1]):
                    update_values['protocol'] = f'{existing_record[1]}, {values_list[1]}'
            if not existing_record[2] and values_list[2]:
                update_values['ip'] = values_list[2]
            elif existing_record[2] != values_list[2]:
                update_values['ip'] = values_list[2]            # Overwrite the IP address w/ newer data
            if (not existing_record[3] and values_list[3]) or (existing_record[3] != values_list[3] and int(existing_record[11]) < int(values_list[11])):
                update_values['id'] = values_list[3]            #If existing ID value is less weight than new value, update record values
                update_values['id_weight'] = values_list[11]
            if (not existing_record[4] and values_list[4]) or (existing_record[4] != values_list[4] and int(existing_record[12]) < int(values_list[12])):
                update_values['name'] = values_list[4]
                update_values['name_weight'] = values_list[12]
            if (not existing_record[5] and values_list[5]) or (existing_record[5] != values_list[5] and int(existing_record[13]) < int(values_list[13])):
                update_values['vendor'] = values_list[5]
                update_values['vendor_weight'] = values_list[13]
            if (not existing_record[6] and values_list[6]) or (existing_record[6] != values_list[6] and int(existing_record[14]) < int(values_list[14])):
                update_values['hw'] = values_list[6]
                update_values['hw_weight'] = values_list[14]
            if (not existing_record[7] and values_list[7]) or (existing_record[7] != values_list[7] and int(existing_record[15]) < int(values_list[15])):
                update_values['sw'] = values_list[7]
                update_values['sw_weight'] = values_list[15]
            if (not existing_record[8] and values_list[8]) or (existing_record[8] != values_list[8] and int(existing_record[16]) < int(values_list[16])):
                update_values['productID'] = values_list[8]
                update_values['productID_weight'] = values_list[16]
            if (not existing_record[9] and values_list[9]) or (existing_record[9] != values_list[9] and int(existing_record[17]) < int(values_list[17])):
                update_values['serial'] = values_list[9]
                update_values['serial_weight'] = values_list[17]
            if (not existing_record[10] and values_list[10]) or (existing_record[10] != values_list[10] and int(existing_record[18]) < int(values_list[18])):
                update_values['device_type'] = values_list[10]
                update_values['device_type_weight'] = values_list[18]

            # Update the record with new values by appending DB fields to SQL query based on values within the 'update_values' array
            if update_values:
                update_query = ', '.join([f"{field} = ?" for field in update_values.keys()])
                update_query += ', updated = ?, timestamp = ? WHERE mac = ?'
                # TO DO ## LOGIC FOR 
                update_values['updated'] = False
                update_values['timestamp'] = datetime.now().strftime("%H:%M:%S")
                self.cursor.execute(f"UPDATE endpoints SET {update_query}", (*update_values.values(), values_list[0]))
                records_updated += 1
                # print(f'record updated - {update_values}')
                logger.debug(f'endpoint db record updated: {values_list[0]} - {values_list[1]} data')
                
        else:
            ## Insert the new endpoint into the database w/ relative fields, but 'FALSE' for 'updated' status
            self.cursor.execute('''
                INSERT INTO endpoints (
                    mac, protocol, ip, 
                    id, name, vendor, hw, sw, productID, serial, device_type, 
                    id_weight, name_weight, vendor_weight, hw_weight, sw_weight, productID_weight, serial_weight, device_type_weight, 
                    updated, timestamp
                )
                VALUES (?, ?, ?, 
                        ?, ?, ?, ?, ?, ?, ?, ?, 
                        ?, ?, ?, ?, ?, ?, ?, ?, 
                        ?, ?)''',
                (values_list[0], values_list[1], values_list[2], 
                 values_list[3], values_list[4], values_list[5], values_list[6], values_list[7], values_list[8], values_list[9], values_list[10], 
                 values_list[11], values_list[12], values_list[13], values_list[14], values_list[15], values_list[16], values_list[17], values_list[18],
                 False, datetime.now().strftime("%H:%M:%S")))
            # print(f'sqldb record created - {values_list}')
            logger.debug(f'endpoint db record created: {values_list[0]} - {values_list[1]} data')
            records_created += 1

        self.connection.commit()

    ## Function for data validation (replace this with your logic)
    def view_all_entries(self):
        self.cursor.execute('SELECT * FROM endpoints')
        entries = self.cursor.fetchall()
        
        print("All Entries in the 'endpoints' table:")
        column_names = [description[0] for description in self.cursor.description]
        print('|'.join(column_names))
        for row in entries:
            print('|'.join(map(str,row)))
    
    ## View all entries in local DB with records that have not been updated and return as object
    def get_active_entries(self):
        self.cursor.execute('SELECT * FROM endpoints WHERE updated = 0')
        entries = self.cursor.fetchall()
        return entries

    async def get_active_entries_async(self):
        self.cursor.execute('SELECT * FROM endpoints WHERE updated = 0')
        entries = self.cursor.fetchall()
        logger.debug(f'number of sqlite3 entries: {len(entries)}')
        return entries

    ## Modify local DB record 'Update' status to 'True' to avoid being included in future updates until new data is available
    async def ise_endpoint_updated(self, mac):
        global ise_updates
        self.cursor.execute('UPDATE endpoints SET updated = 1 WHERE mac = ?', (mac,))
        ise_updates += 1

    def view_stats(self):
        logger.debug(f'Local DB records created: {records_created}')
        logger.debug(f'Local DB records updated: {records_updated}')
        logger.debug(f'Local DB records sent to ISE: {ise_updates}')

    def close_connection(self):
        self.connection.close()
