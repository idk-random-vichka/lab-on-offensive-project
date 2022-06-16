import netifaces as ni
from scapy.all import *
import spoofing_tool as spoof

# main function
def search_hosts(_iface):
    ip = ni.ifaddresses(_iface)[ni.AF_INET][0]['addr']
    network_mask = ni.ifaddresses(_iface)[ni.AF_INET][0]['netmask']

    ip_network_part = network(ip,network_mask)
    subnet_length = ip2bin(network_mask).count("1")

    network_addr = str(ip_network_part+"/"+str(subnet_length))

    ans, un_ans = arping(network_addr)

    i = 0
    active_hosts = []
    my_addresses = get_my_details(_iface)
    active_hosts.append({"ip": my_addresses["ip"], "mac": my_addresses["mac"], "cmmnt": " (this device)"})
    for host in ans:
        ip_address = host[1][ARP].psrc
        mac_address = str(host[1][ARP].hwsrc).lower()

        current_tuple= {"ip": ip_address, "mac": mac_address, "cmmnt": ""}
        active_hosts.append(current_tuple)
        i+=1

    print_active_hosts(active_hosts, len(ans)+len(un_ans), network_addr)

    return active_hosts

def get_my_details(_iface): 
    ip_address = ni.ifaddresses(_iface)[ni.AF_INET][0]['addr']
    mac_address = ni.ifaddresses(_iface)[ni.AF_LINK][0]['addr']
    return {"ip": ip_address, "mac": mac_address}

def print_active_hosts(active_hosts, num_scanned, net_addr): 
    num_active = len(active_hosts)
    spoof.printf("Found {} active hosts out of {} scanned (Network CIDR: {}):".format(num_active,num_scanned, net_addr))
    for i in range(len(active_hosts)):
        host = active_hosts[i]
        spoof.printf("\t" + str(i+1) + ". " + "MAC: " + host["mac"] + "\tIP: " + host["ip"] + host["cmmnt"])

def ip2bin(ip):
    octets = map(int, ip.split('/')[0].split('.')) # '1.2.3.4'=>[1, 2, 3, 4]
    binary = '{0:08b}{1:08b}{2:08b}{3:08b}'.format(*octets)
    range = int(ip.split('/')[1]) if '/' in ip else None
    return binary[:range] if range else binary

def network(ip,mask):
    network = ''

    iOctets = ip.split('.')
    mOctets = mask.split('.')

    network = str( int( iOctets[0] ) & int(mOctets[0] ) ) + '.'
    network += str( int( iOctets[1] ) & int(mOctets[1] ) ) + '.'
    network += str( int( iOctets[2] ) & int(mOctets[2] ) ) + '.'
    network += str( int( iOctets[3] ) & int(mOctets[3] ) )

    return network

# call main
if __name__=="__main__":
    search_hosts("")