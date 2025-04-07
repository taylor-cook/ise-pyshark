# ise-pyshark
 
This repository contains the source code for performing custom Deep Packet Inspection (DPI) on observed network traffic and then sharing that contextual data with a Cisco Identity Services Engine (ISE) deployment.  This tool is **NOT an officially supported Cisco tool**, but services to improve overall profiling data of ISE endpoints via the use of existing API structures.  This concept relies on deploying 'collectors' throughout a network environment which will receive endpoint traffic, inspect the traffic using the "pyshark" Python library, and then update endpoints within ISE via API calls into the ISE Endpoint Database (detailed below). 

The contained code relies on the assumption that various protocols transmitted by endpoints are never seen by ISE due to either due to L3 boundaries or other mechanisms but can be analyzed to provide additional endpoint context.  This includes better identification of IoT endpoints using mDNS, UPnP or other protocols to more precisely identifying endpoints based on attributes like User-Agent strings not presented to ISE directly for webauth, and providing more specific details to generic devices already discovered by ISE (ex. Apple Device -> MacBook Air (M1, 2020)). An example of this process with various endpoints are provided below:

![Example ise-pyshark process](/img/ise-pyshark-ex1.png "Example ise-pyshark process.")
![Example ise-pyshark process](/img/ise-pyshark-ex2.png "Example ise-pyshark process.")

This repository uses pyshark to perform all DPI functions, but other packet inspection technologies are also available (scapy, dpkt).

The code included in this repository should be deployed on "collectors" throughout a network environment.  Collectors can be virtual machines (VMs) or even physical workstations as long as they can run Python and have the necessary dependency libraries installed.  A concept of collector deployment within a network is shown below:
![Example collector deployment](/img/collectors.png "Example collector deployment.")

**NOTE**: This code is **not an officially supported integration** for Cisco ISE and as such, the user assumes all risks associated with deploying this code in a production network.  It is recommended to deploy this tool in a test ISE environment and heavily evaluate before considering deployment in production networks.  If required, demo instances of ISE can be downloaded and installed with 90-Day free trials at [www.cisco.com/go/downloads].

# Features

- Dynamic creation/verification of ISE Endpoint Custom Attributes
- Dynamic OUI lookups via IEEE & randomized MAC detection
- Dynamic User-Agent String Lookup
- Dynamic Vendor Model and OS Version lookup
- Weighted certainty factors per attribute
- Dynamic ISE endpoint lookup/verification
- Bulk Endpoint API updates (up to 500 endpoints at a time)
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
3. Install redis and enable service (see https://redis.io for details per OS)
4. Optionally (**but strongly recommended**) create a virtual environment using **python venv**
5. Install the ise-pyshark module using pip:

        pip3 install ise-pyshark

# Configuration Steps
1. Configure an ISE Administrator account with ERS Admin access
2. Configure SPAN / ERSPAN on switch infrastructure to point to collector -- recommend filtering ERSPAN traffic using template below
3. Start the collector via cli with the following command:
```
ise-pyshark -u <username> -p <password> -a <hostname> -i <interface_name>
```
Other optional arguments:
```
-D    Enable debug-level messages
```
**NOTE:** Linux users will need to run above commands as "sudo" due to updates required to installed ise-pyshark pkg files.


# Analyze existing PCAP(NG) File
Peform analysis on an existing wirecapture file then export data to CSV and/or update ISE endpoint records
- Requires ISE admin credentials and local packet capture PCAP(NG) file
```
ise-pyshark-file
```
Once file parsed, data can be optionally be exported to CSV or sent to ISE via API updates:
```
Export the endpoint data from PCAP(NG) file to a local CSV file? [y/n]: 
Export the endpoint data from PCAP(NG) file to ISE [y/n]:  
ISE Admin Node IP Address: <ISE PAN IP>
ISE API Admin Username: <Username>
ISE API Admin Password: <Password>
```

# Steps for installing in Ubuntu VM to run as Collector (Ubuntu 22.04 LTS)
```
sudo apt-get update
sudo apt install python3-pip -y
sudo apt install redis-server -y
sudo apt install tshark -y
(Select Yes)
sudo pip install ise-pyshark
sudo systemctl enable redis-server
sudo systemctl start redis-server
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

# Limitations
- Only inspects protocols listed above
- Does not inspect IPv6 traffic
- Recommend ISE 3.1+ version (3.3, 3.4 tested)

# Removing / Uninstall
- All ISE data is stored within CustomAttribute fields for endpoints, therefore deleting those CustomAttribute fields will remove all data added by the ise-pyshark utility
![Removing ise-pyshark data from ISE](/img/ise-pyshark-delete.png "Removing ise-pyshark data from ISE.")
- Collectors can simply be decomissioned or run the requisite "pip uninstall ise-pyshark" command

# Other Points
- Repository only contains code for deployment on collectors.  Custom profile definitions within ISE based on observed data and custom policy rule creation in ISE referencing custom profiles is the responsibility of the Network Adminstrator and is beyond the scope of this code.

# Feedback
Author - Taylor Cook

Email - aacook@cisco.com