### IMPORTS ###

from playsound import playsound # pip install
from scapy.all import *
import netifaces as ni # pip install

# standard libraries
from os import system, name
import signal
import sys, os

# import other files from project
import arp_spoofing as arp
import dns_spoofing as dns
import lovec_ribar as l_r


### CONSTANTS ###

INPUT_INDEX = 7
PRINT_INDEX = -1
DEFAULT_IFACE = "lo"


### VARIABLES ###

verbose = False # mute outputs
gratuitious = False # arp setting


### FUNCTIONS ###

def main():
    conf.verb = 0

    clear()
    printf("Welcome to our tool for spoofing!", 0)
    printf("")
    playsoundf("resources/windows_xp_startup.mp3", verbose)
    lovec_and_ribar()

def lovec_and_ribar():
    previous_tuples = [["Pick an attack: DNS(d), ARP(a) or L&R(lr)", 1]]
    print_previous(previous_tuples)

    while True:
        _input = inputf(previous_tuples).lower()
        if _input in ["arp", "a"]:
            arp.arp_spoofing(gratuitious, verbose)
            break
        elif _input in ["dns", "d"]:
            dns.dns_spoofing(gratuitious, verbose)
            break
        elif _input in ["l&r", "lr"]:
            l_r.lovec_ribar()
            break
        else:
            printf("Invalid Input. Try again!", 2)

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
        iface = DEFAULT_IFACE

    # choose interface
    previous_tuples.append(["Available interfaces:"])

    for i in range(len(interfaces)):
        previous_tuples.append(["\t"+str(i+1) + ": " + interfaces[i]])

    previous_tuples.append([""])
    previous_tuples.append(["Choose interface("+str(1)+"-"+str(len(interfaces))+") or default(d):", 1])
    print_previous(previous_tuples)

    _valid = True
    previous_tuples = []
    user_input = inputf(previous_tuples)
    if user_input.lower() not in ["default","d"]:
        if user_input.strip().isdigit():
            iface = interfaces[int(user_input) - 1]
        elif user_input in interfaces:
            iface = user_input
        else:
            _valid = False
            previous_tuples.append(["Invalid input. Choosing default interface ({}).".format(iface), 2])
            previous_tuples.append(["---------------------------------------------" + "-" * len(iface)])
    
    if _valid:
        previous_tuples.append(["Chosen interface: " + iface, 0])
        previous_tuples.append(["------------------" + "-" * len(iface)])


    previous_tuples.append(["Searching for active hosts in the subnet..."])
    previous_tuples.append([""])

    return iface, previous_tuples

def validate_ip(active_hosts, other_ips, previous_tuples=[]):
    ip_is_valid = False
    curr_ip = inputf(previous_tuples)
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

    if (curr_ip in other_ips):
        printf("Target repeated! Try again:", 2)
        return validate_ip(active_hosts, other_ips, previous_tuples)
    elif (ip_is_valid == True):
        return correct_tuple
    else:
        printf("Invalid IP. Try again:", 2)
        return validate_ip(active_hosts, other_ips, previous_tuples)

def printf(text, i=PRINT_INDEX, verbose=False):
    if not verbose:
        print(style_str(i) + str(text))

def inputf(previous_tuples=[], eend=""):
    _input = input(style_str(INPUT_INDEX) + eend)
    if _input.lower() in ["q", "quit"]:
        clear()
        printf("Are you sure you want to exit the application?", 1)
        if choice():
            sys.exit()
        else:
            print_previous(previous_tuples, True)
            _input = inputf(previous_tuples, eend)
    elif _input.lower() in ["r", "reset"]:
        clear()
        lovec_and_ribar()
    elif _input.lower() in ["h", "help"]:
        clear()
        lovec_and_ribar()

    return _input

def choice():
    while True:
        _inp = inputf().lower()
        if _inp in ["y", "yes", "ye"]:
            return True
        elif _inp in ["n", "no"]:
            return False
        else:
            printf("Invalid Input. Try again!", 2)

def playsoundf(str, verbose=False):
    if not verbose:
        playsound(str)

def style_str(i=PRINT_INDEX):
    res = "|L&R| "

    if i == -1:
        res += "[ ]" 
    elif i == 0:
        res += "[+]" # Beginning of section  
    elif i == 1:
        res += "[?]" # Question
    elif i == 2:
        res += "[!]" # Invalid input / Warning
    elif i == 3:
        res += "[X]" # Closing application
    elif i == 4:
        res += "[.]" # ARP Poison
    elif i == 5:
        res += "[#]" # DNS Spoof
    elif i == 6:
        res += "[=]" 
    elif i == 7:
        res += "[>]" # Input
    else:
        res += "[ ]"

    return res + " "

def print_previous(previous_tuples, clear_screen=False):
    if clear_screen:
        clear()

    for _tuple in previous_tuples:
        try:
            printf(_tuple[0], _tuple[1])
        except:
            printf(_tuple[0])

def clear():
    # for windows
    if name == 'nt':
        _ = system('cls')

    # for mac and linux
    else:
        _ = system('clear')

def should_ip_forward(should_forward):
    # for windows
    if name == 'nt':
        from services import WService
        serv = WService("RemoteAccess")
        if should_forward:
            serv.start()
        else:
            serv.stop()

    # for linux
    else:
        import subprocess
        if should_forward:
            forw = "1"
        else:
            forw = "0"
        subprocess.call(["sysctl", "-w", "net.ipv4.ip_forward="+forw], stdout=open(os.devnull, "wb"))

def handler(signum, frame):
    lovec_and_ribar()

def quit_sequence():
        printf("Closed: Lovec & Ribar.", 3)
        playsoundf("resources/windows_xp_shutdown.mp3", verbose)

# call main
if __name__=="__main__":
    signal.signal(signal.SIGTSTP, handler)
    try:
        main()
    except KeyboardInterrupt:
        print(" (KeyboardInterrupt)")
        quit_sequence()    
    except SystemExit:
        print(" (SystemExit)")
        quit_sequence()
    except:
        printf("Unexpected error!", 2)
        printf(sys.exc_info()[1], 2)
        printf("")
        quit_sequence()
    # main()