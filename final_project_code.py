from scapy.all import *
import netifaces as ni
import arp_spoofing as arp
import search_hosts as sh
import spoofing_tool as spoof
import sys

default_iface = "lo"

def main():
    conf.verb = 0

    iface = get_interface()

    spoof.printf("")
    spoof.printf("Searching for active hosts in the subnet...", 4)
    active_hosts = sh.search_hosts(iface)

    spoof.printf("")
    spoof.printf("Input IP address of the first target out of the active hosts:", 1)
    first_target = validate_ip(active_hosts, "")
    
    spoof.printf("")
    spoof.printf("Input IP address of the second target out of the active hosts("+str(1)+"-"+str(len(active_hosts))+"):", 1)
    second_target = validate_ip(active_hosts, first_target["ip"])

    my_details = sh.get_my_details(iface)
    arp.arp_spoofing(first_target["mac"], first_target["ip"], second_target["mac"], second_target["ip"], my_details["mac"], my_details["ip"], iface)
    

def get_interface(previous_tuples=[]):
    # get available interfaces
    interfaces = get_if_list()

    # remove loopback interface (used to communicate with itself) if available
    try: 
        interfaces.remove("lo")
    except: 
        pass

    # set default interface
    try: 
        iface = ni.gateways()["default"][2][1]
    except:
        iface = default_iface

    # choose interface
    try:
        previous_tuples.append(["Available interfaces:"])

        for i in range(len(interfaces)):
            previous_tuples.append(["\t"+str(i+1) + ": " + interfaces[i]])

        previous_tuples.append([""])
        previous_tuples.append(["Choose interface("+str(1)+"-"+str(len(interfaces))+") or default(d):", 1])
        spoof.print_previous(previous_tuples)

        user_input = spoof.inputf(7, "", previous_tuples)
        if user_input.lower() not in ["default","d"]:
            if user_input.strip().isdigit():
                iface = interfaces[int(user_input) - 1]
            elif user_input in interfaces:
                iface = user_input
            else:
                raise # throw Exception
        previous_tuples = []
        previous_tuples.append(["Chosen interface: " + iface, 0])
        previous_tuples.append(["------------------" + "-" * len(iface)])
    except:
        previous_tuples = []
        previous_tuples.append(["Invalid input. Choosing default interface ({}).".format(iface), 2])
        previous_tuples.append(["---------------------------------------------" + "-" * len(iface)])

    return iface, previous_tuples
    

def validate_ip(active_hosts, other_ip, previous_tuples=[]):
    ip_is_valid = False
    curr_ip = spoof.inputf(7, "", previous_tuples)
    correct_tuple = {}

    if curr_ip.strip().isdigit():
        curr_ip = int(curr_ip)
        if curr_ip > 0 and curr_ip < len(active_hosts) + 1:
            curr_ip = active_hosts[int(curr_ip) - 1]["ip"]

    for host in active_hosts:
        if (str(host["ip"]) == curr_ip):
            correct_tuple = host
            ip_is_valid = True
            break

    if (curr_ip == other_ip):
        spoof.printf("The second target cannot be the same as the first. Try again:", 2)
        return validate_ip(active_hosts, other_ip, previous_tuples)
    elif (ip_is_valid == True):
        #spoof.print_previous(previous_tuples)
        return correct_tuple
    else:
        spoof.printf("Invalid IP. Try again:", 2)
        return validate_ip(active_hosts, other_ip, previous_tuples)

# call main
if __name__=="__main__":
    main()