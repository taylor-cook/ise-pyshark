# ise-pyshark
 
This repository contains the source code for performing custom Deep Packet Inspection (DPI) on observed network traffic and then sharing that contextual data with a Cisco Identity Services Engine (ISE) deployment.  This tool serves as an **CONCEPT** (non-TAC supported) of how to improve overall profiling efficacy of ISE endpoints via the use of existing API structures.  This concept relies on deploying 'collectors' throughout a network environment which will receive endpoint traffic, inspect the traffic using the "pyshark" Python library, and then update endpoints within ISE via pxGrid APIs into the endpoint "asset" fields (detailed below). 

The contained code relies on the assumption that various protocols transmitted by endpoints are never seen by ISE due to either due to L3 boundaries or other mechanisms but can be analyzed to provide additional endpoint context.  This includes better identification of IoT endpoints using UPnP, more precisely identifying endpoints based on User-Agent strings not presented to ISE directly for webauth, and providing more specific details to generic devices already discovered by ISE (ex. Apple Device -> MacBook Air (M1, 2020)). An example of this process with various endpoints are provided below:

![Example ise-pyshark process](/img/ise-pyshark-ex1.png "Example ise-pyshark process.")
![Example ise-pyshark process](/img/ise-pyshark-ex2.png "Example ise-pyshark process.")

This repository uses pyshark to perform all DPI functions, but other packet inspection technologies are also available (scapy, dpkt).  This repository leverages the 'pxgrid-util' python library for interactions with ISE.  More information can be found at [https://developer.cisco.com/codeexchange/github/repo/cisco-pxgrid/python-advanced-examples/] 

The code included in this repository should be deployed on "collectors" throughout a network environment.  Collectors can be virtual machines (VMs) or even physical workstations as long as they can run Python and have the necessary dependency libraries installed.  A concept of collector deployment within a network is shown below:
![Example collector deployment](/img/collectors.png "Example collector deployment.")

**NOTE**: This code is a **concept** only, and not an officially supported integration for Cisco ISE and as such, the user assumes all risks associated with deploying this code in a production network.  It is recommended to deploy this tool in a test ISE environment and heavily evaluate before considering deployment in production networks.  This will allow for fine-tuning of protocol analysis an updates via pxGrid.  If required, demo instances of ISE can be downloaded and installed with 90-Day free trials at [www.cisco.com/go/downloads].

# Features

- Cisco ISE pxGrid Account Activation
- Cert-Based ISE pxGrid Connection
- Local sqlite3 DB caching
- Dynamic OUI lookups via IEEE
- Dynamic User-Agent String Lookup
- Dynamic Vendor Model and OS Version lookup
- Randomized MAC detection
- Weighted certainty factor
- Supported Protocols
  - mDNS
  - SSDP
  - HTTP
  - SIP
  - XML
  - SMB
- Supported Traffic Ingest Methods
  - Switchport Analyzer (SPAN)
  - Encapsulated Remote SPAN (ERSPAN)

# Required Installation Steps:
All the examples may be installed using `pip`, making the examples available in your environment.

1. Have **Python 3.8 or later** available on your system
2. Install the [tshark package (or the full Wireshark package)](https://tshark.dev/setup/install/)
3. Optionally (**but strongly recommended**) create a virtual environment using **python venv**
4. Install the ise-pyshark module using pip:

        pip3 install ise-pyshark

# Configuration Steps
1. Generate pxgrid client certificate and key (see below for detailed instructions)
2. Store pxGrid certificates in same directory where script will be executed
3. Configure SPAN / ERSPAN on switch infrastructure to point to collector -- recommend filtering ERSPAN traffic using template below
4. Start the collector via cli with the following command (per pxgrid-util library):
```
ise-pyshark \
-a <hostname> \
-n <nodename> \
-c <pxgrid-client>.cer \
-k <pxgrid-client>.key \
-s <root_ca>.pem \
--interface <interface_name>
```
Other optional arguments:
```
-p <cleartext>  Cleartext password for PEM file
--verbose       Shows detailed logs as script runs.
```
Additional arguments can be added to override default values (**use with caution**):
```
--service <custom_pxgrid_service>
--topic <custom_pxgrid_topic>
```
**NOTE** If an existing DB file is found, option to append new data or wipe and start new.
**NOTE** Linux users will need to run above commands as "sudo" due to live updates to ise-pyshark pkg files.


# ISE pxGrid Update Example

Endpoint detail updates sent to ISE via ise-pyshark use the pxGrid 'context-in' API call in the following structure:
```
{
    "opType": "UPDATE",
    "asset": {
        "assetId": "",
        "assetName": "",
        "assetIpAddress": "",
        "assetMacAddress": "",
        "assetVendor": "",
        "assetHwRevision": "",
        "assetSwRevision": "",
        "assetProtocol": "",
        "assetProductId": "",
        "assetSerialNumber": "",
        "assetDeviceType": ""
    }
}
```
# Configure ERSPAN data (example C9300 IOS-XE)
```
(config)#ip access-list extended ERSPAN-ACL
(config-ext-nacl)# 10 permit udp any any eq 5353
(config-ext-nacl)# 20 permit udp any any eq 1900
(config-ext-nacl)# 30 permit udp any any eq 5060
(config-ext-nacl)# 40 permit tcp any any eq 80
(config-ext-nacl)# 50 permit tcp any any eq 8080
(config-ext-nacl)# 60 permit udp any any eq 138
(config-ext-nacl)# exit
(config)#
(config)# monitor session <id> type erspan-source
(config-mon-erspan-src)# source interface <int x/x> rx
(config-mon-erspan-src)# source interface <int x/y - z> rx
(config-mon-erspan-src)# filter ip access-group ERSPAN-ACL
(config-mon-erspan-src)# destination
(config-mon-erspan-src-dst)# erspan-id <erspan-id>
(config-mon-erspan-src-dst)# ip address <collector ip>
(config-mon-erspan-src-dst)# exit
(config-mon-erspan-src)# no shut
(config-mon-erspan-src)# end
```
More details available here [https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9300/software/release/16-11/configuration_guide/nmgmt/b_1611_nmgmt_9300_cg/configuring_erspan.html]

# Test on existing PCAP(NG) File
Peform a test analysis on an existing wirecapture file
- Requires only local PCAP(NG) file 
```
ise-pyshark-file

Input local pcap(ng) file to be parsed: <file-location>/<file>.pcapng
Input custom wireshark display filter (leave blank to use built-in display filter): 
```
Once analysis is completed, all parsed endpoint data is displayed with the relevant "asset" attributes which would be used to update endpoints in ISE (ex. assetName, assetVendor, ...) 

**NOTE** Running this pcap file test DOES NOT send any updates to ISE servers.
Example Output:
```
#######################################
##      Resulting Endpoint Data      ##
#######################################
All Entries in the 'endpoints' table:
('12:93:93:XX:XX:XX', 'mDNS', '192.168.1.143', '', 'iPhone (9)', 'Unknown (randomized MAC)', 'iPhone 13', '', 'model=D17AP', '', '', 0, 80, 0, 80, 0, 80, 0, 0, '20:51:00', 0)
('6c:02:e0:XX:XX:XX', 'mDNS', '192.168.1.2', '', 'HP Color LaserJet Pro M478f-9f [C24C95]', 'HP', 'HP Color LaserJet Pro MFP M478f-9f', '', 'usb_MDL=Color LaserJet Pro M478f-9f', '', '', 0, 80, 50, 80, 0, 80, 50, 0, '20:51:01', 0)
('42:99:21:XX:XX:XX', 'mDNS', '192.168.1.233', '', 'iPhone (24)', 'Unknown (randomized MAC)', 'iPhone 14 Pro Max', '', 'model=D74AP', '', '', 0, 80, 0, 80, 0, 80, 0, 0, '20:51:00', 0)
('28:56:5a:XX:XX:XX', 'mDNS', '192.168.1.132', '', 'Brother MFC-L5850DW series', 'Brother', 'Monochrome All-in-One Printer (2-sided, 42ppm)', '', 'usb_MDL=MFC-L5850DW series', '', '', 0, 80, 50, 80, 0, 80, 50, 0, '20:51:01', 0)
```
# View Existing Database File #
Check existing endpoint data already collected from live capture or existing PCAP parsing
- ise-pyshark-view

# Limitations
- Only inspects protocols listed above
- Does not inspect IPv6 traffic
- Recommend ISE 3.1+ version (3.2, 3.3 tested)

# Other Points
- Repository only contains code for deployment on collectors.  Custom profile definitions within ISE based on observed data and custom policy rule creation in ISE referencing custom profiles is the responsibility of the Network Adminstrator and is beyond the scope of this code.

#  Steps for installing in Ubuntu VM to run as Collector (Ubuntu 22.04 LTS)
```
sudo apt-get update
sudo apt install python3-pip -y
sudo apt install tshark -y
(Select Yes)
sudo pip install ise-pyshark
```

#  Generate pxGrid Certificates From ISE

If you wish to mutual cert-based authentication:

- Navigate to ISE Admin GUI via any web browser and authorized login
- Navigate to Administration -> pxGrid Services
- Click on the Certificates tab
- Fill in the form as follows:
    - I want to: **Generate a single certificate (without a certificate signing request)**
        - Common Name (CN): {fill in any name}
        - Certificate Download Format: Certificate in Privacy Enhanced Electronic Mail (PEM) format, key in PKCS8 PEM format (including certificate chain)
        - Certificate Password: {fill in a password}
        - Confirm Password: {fill in the same password as above}
- Click the 'Create' button. A zip file should download to your machine
- Extract the downloaded file.

# Feedback
Author - Taylor Cook
Email - aacook@cisco.com