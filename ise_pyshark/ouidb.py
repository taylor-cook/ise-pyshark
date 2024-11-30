import requests
import csv
import re
import sqlite3
import logging
import pkg_resources

logger = logging.getLogger(__name__)

class ouidb:
    def __init__(self, url, raw_data_file, pipe_file, database_file):
        self.url = url
        self.raw_data_file = pkg_resources.resource_filename('ise_pyshark', raw_data_file)
        self.pipe_file = pkg_resources.resource_filename('ise_pyshark', pipe_file)
        self.database_file = pkg_resources.resource_filename('ise_pyshark', database_file)
        # self._initialize_database()

    def _initialize_database(self):
        self.download_macoui_data()
        self.create_pipe_separated_file()
        self.import_to_sqlite()

    def download_macoui_data(self):
        logger.debug('downloading OUI db - starting')
        response = requests.get(self.url)
        with open(self.raw_data_file, 'wb') as f:
            f.write(response.content)
        logger.debug('downloading OUI db - complete')

    def create_pipe_separated_file(self):
        logger.debug('parsing OUI db data - starting')
        with open(self.raw_data_file, 'r') as infile, open(self.pipe_file, 'w') as outfile:
            outfile.write("OrgName|OUI\n")
            for line in infile:
                line = line.rstrip('\n')
                if match := re.match(r'^([0-9A-F]{2})-([0-9A-F]{2})-([0-9A-F]{2})\s+\(hex\)\s+(.+)$', line):
                    orgname, oui = match.group(4), match.group(1) + match.group(2) + match.group(3)
                    outfile.write(f"{orgname}|{oui}\n")
        logger.debug('parsing OUI db data - complete')

    def import_to_sqlite(self):
        logger.debug('create OUI db table - starting')
        connection = sqlite3.connect(self.database_file)
        cursor = connection.cursor()

        # Delete any pre-existing DB data
        cursor.execute('DROP TABLE IF EXISTS macoui')

        # Create the macoui table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS macoui (
                OrgName TEXT,
                OUI TEXT
            )
        ''')

        # Import data into the macoui table
        with open(self.pipe_file, 'r') as f:
            reader = csv.reader(f, delimiter='|')
            next(reader)  # Skip header
            cursor.executemany('INSERT OR REPLACE INTO macoui (OrgName, OUI) VALUES (?, ?)', reader)

        # Add indices on each column
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_oui ON macoui (OUI)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_orgname ON macoui (OrgName)')

        # Commit changes and close connection
        connection.commit()
        connection.close()
        logger.debug('create OUI db table - complete')

    def query_mac_address(self, mac_address):
        connection = sqlite3.connect(self.database_file)
        cursor = connection.cursor()

        # Query the OrgName for the given MAC address
        cursor.execute('SELECT OrgName FROM macoui WHERE OUI = ?', (mac_address,))
        result = cursor.fetchone()
        connection.close()

        # Print the result
        if result:
            return result[0]
        else:
            return None