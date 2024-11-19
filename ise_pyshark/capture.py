import pyshark
import logging
from pxgrid_pyshark import endpointsdb
from pxgrid_pyshark import parser

## DEDICATED CLASS FOR ALL PACKET PARSING FUNCTIONS

logger = logging.getLogger(__name__)
# parser = parser()

## Create dict of supported protocols and their appropriate inspection functions
packet_callbacks = {
    'sip': parser.parse_sip,
    'ssdp': parser.parse_ssdp,
    'mdns': parser.parse_mdns,
    'http': parser.parse_http,
    'xml': parser.parse_xml
}

class capture:
    ## Initialize endpoints database and parser
    def __init__(self):
        self.endpoints = endpointsdb()
        self.parser = parser()

    ## Process network packets using global Parser instance and dictionary of supported protocols
    def process_packet(self, packet):
        try:
            highest_layer = packet.highest_layer
            inspection_layer = str(highest_layer).split('_')[0]
            ## If XML traffic included over HTTP, match on XML parsing
            if inspection_layer == 'XML':
                fn = parser.parse_xml(packet)
                if fn is not None:
                    self.endpoints.update_db_list(fn)
            else:
                for layer in packet.layers:
                    fn = packet_callbacks.get(layer.layer_name)
                    if fn is not None:
                        self.endpoints.update_db_list(fn(packet))
        except Exception as e:
            logger.error(f'error processing packet details {highest_layer}: {e}')
    
    ##
    def capture_live_packets(self, network_interface, filter):
        try:
            logger.debug(f'beginning live capture of {network_interface}')
            capture = pyshark.LiveCapture(interface=network_interface, only_summaries=False, include_raw=True, use_json=True, display_filter=filter)
            currentPacket = 0
            for packet in capture.sniff_continuously():
                ## Wrap individual packet processing within 'try' statement to avoid formatting issues crashing entire process
                try:
                    self.process_packet(packet)
                except Exception as e:
                    logger.error(f'error processing packet: {currentPacket}: {e}')
                currentPacket += 1
        except Exception as e:
            logger.error(f'live capture process crashed: {e}')
            sys.exit(1)

    def process_capture_file(self, capture_file, capture_filter):
        if Path(capture_file).exists():
            logger.warning(f'processing capture file: {capture_file}')
            # start_time = time.perf_counter()
            capture = pyshark.FileCapture(capture_file, display_filter=capture_filter, only_summaries=False, include_raw=True, use_json=True)
            capture = pyshark.FileCapture()
            currentPacket = 0
            for packet in capture:
                ## Wrap individual packet processing within 'try' statement to avoid formatting issues crashing entire process
                try:
                    process_packet(packet)
                except Exception as e:
                    logger.error(f'Error processing packet: {capture_file}, packet # {currentPacket}: {e}')
                currentPacket += 1
            capture.close()
            # end_time = time.perf_counter()
            # logger.warning(f'processing capture file complete: execution time: {end_time - start_time:0.6f} : {currentPacket} packets processed ##')
        else:
            logger.error(f'capture file not found: {capture_file}')            