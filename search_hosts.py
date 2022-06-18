import netifaces as ni
from scapy.all import *

# Import other files from project
import spoofing_tool as spoof

# Function that searches for all available hosts on the provided {@iface} 
# @returns array of active hosts as dictionary with 'ip', 'mac' and 'cmmnt' (comment)
#
# passed argument {@previous_tuples} for correct UI (terminal printing)
def search_hosts(_iface, previous_tuples=[]):
    # get my ip on the interface and extract the network mask
    ip = ni.ifaddresses(_iface)[ni.AF_INET][0]['addr']
    network_mask = ni.ifaddresses(_iface)[ni.AF_INET][0]['netmask']

    # get subnet ip with 0's as host part and length of subnet part of ip
    ip_network_part = network(ip,network_mask)
    subnet_length = ip2bin(network_mask).count("1")
    network_addr = str(ip_network_part+"/"+str(subnet_length))

    # scapy function that searches for active hosts on the provided network
    ans, un_ans = arping(network_addr)

    # array of active hosts; each host is represented by an 'ip', 'mac' and 'cmmnt' (comment)
    active_hosts = []

    # add my ip and mac to the currently active hosts
    my_addresses = get_my_details(_iface)
    active_hosts.append({"ip": my_addresses["ip"], "mac": my_addresses["mac"], "cmmnt": " (this device)"})

    # add the other active hosts from the output of arping
    for host in ans:
        ip_address = host[1][ARP].psrc
        mac_address = str(host[1][ARP].hwsrc).lower()

        current_tuple= {"ip": ip_address, "mac": mac_address, "cmmnt": ""}
        active_hosts.append(current_tuple)
    
    # update previous_tuples for UI
    _previous_tuples = print_active_hosts(active_hosts, len(ans)+len(un_ans), network_addr, previous_tuples)

    return active_hosts, _previous_tuples

# Function that returns this machine's IP and MAC addresses on the specified interface
def get_my_details(_iface): 
    ip_address = ni.ifaddresses(_iface)[ni.AF_INET][0]['addr']
    mac_address = ni.ifaddresses(_iface)[ni.AF_LINK][0]['addr']
    return {"ip": ip_address, "mac": mac_address}

# Function for printing the active hosts for the UI
# @returns the previous tuples to be printed
#
# @param _pr is a boolean value for deciding whether active hosts should be printed inside this function
def print_active_hosts(active_hosts, num_scanned, net_addr, previous_tuples=[], _pr=True): 
    if _pr:
        previous_tuples.append(["Found {} active hosts out of {} scanned (Network CIDR: {}):".format(len(active_hosts),num_scanned, net_addr)])

    for i in range(len(active_hosts)):
        host = active_hosts[i]
        previous_tuples.append(["\t" + str(i+1) + ". " + "MAC: " + host["mac"] + "\tIP: " + host["ip"] + host["cmmnt"]])

    if _pr:
        spoof.print_previous(previous_tuples)

    return previous_tuples

# Function fro converting an IP address to a Binary string
def ip2bin(ip):
    octets = map(int, ip.split('/')[0].split('.')) # '1.2.3.4'=>[1, 2, 3, 4]
    binary = '{0:08b}{1:08b}{2:08b}{3:08b}'.format(*octets)
    range = int(ip.split('/')[1]) if '/' in ip else None
    return binary[:range] if range else binary

# Function extracting the network ip from a mask and an ip
# example: 
#   ip     = 100.101.102.103 
#   mask   = 255.255.255.0
#   result = 100.101.102.0
def network(ip,mask):
    network = ''

    iOctets = ip.split('.')
    mOctets = mask.split('.')

    network = str( int( iOctets[0] ) & int(mOctets[0] ) ) + '.'
    network += str( int( iOctets[1] ) & int(mOctets[1] ) ) + '.'
    network += str( int( iOctets[2] ) & int(mOctets[2] ) ) + '.'
    network += str( int( iOctets[3] ) & int(mOctets[3] ) )

    return network