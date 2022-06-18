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

# Main function that is executed when the tool is started
def main():
    # mute the output of scapy
    conf.verb = 0

    # clear the terminal and print the welcome message
    clear()

    # play the starting sound
    playsoundf("resources/windows_xp_startup.mp3", verbose)

    # choose the attack you wish to do
    choose_main_attack()

# Function that picks an attack based on user input
def choose_main_attack():
    previous_tuples = [["Pick an attack: DNS(d), ARP(a) or L&R(lr)", 1]]
    print_previous(previous_tuples)

    while True:
        # get the user's input
        _input = inputf(previous_tuples).lower()

        if _input in ["arp", "a"]:
            # start arp attack
            arp.arp_spoofing(gratuitious)
            # allow the user to choose a new attack after the current is finished
            choose_main_attack()

        elif _input in ["dns", "d"]:
            # start dns attack
            dns.dns_spoofing(gratuitious)
            # allow the user to choose a new attack after the current is finished
            choose_main_attack()

        elif _input in ["l&r", "lr"]:
            # start lovec and ribar attack
            l_r.lovec_ribar()
            # allow the user to choose a new attack after the current is finished
            choose_main_attack()

        else:
            # when the user's input is invalid
            printf("Invalid Input. Try again!", 2)

# Function that allows the user to pick an interface on which the current attack will be executed
# 
# @return the interface the user chose and the previous_tuples for printing
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

    # print the list of available interfaces
    previous_tuples.append(["Available interfaces:"])
    for i in range(len(interfaces)):
        previous_tuples.append(["\t"+str(i+1) + ": " + interfaces[i]])
    previous_tuples.append([""])
    previous_tuples.append(["Choose interface("+str(1)+"-"+str(len(interfaces))+") or default(d):", 1])
    print_previous(previous_tuples)

    _valid = True
    previous_tuples = []
    user_input = inputf(previous_tuples) # get the user's input

    # if the user did not pick the default interface
    if user_input.lower() not in ["default","d"]:
        # check which interface user chose from the list
        if user_input.strip().isdigit():
            iface = interfaces[int(user_input) - 1]
        elif user_input in interfaces:
            iface = user_input
        # if the input was invalid then select the default interface as the current interface
        else:
            _valid = False
            previous_tuples.append(["Invalid input. Choosing default interface ({}).".format(iface), 2])
            previous_tuples.append(["---------------------------------------------" + "-" * len(iface)])
    
    if _valid:
        previous_tuples.append(["Chosen interface: " + iface, 0])
        previous_tuples.append(["------------------" + "-" * len(iface)])

    # message duisplayed since the next step is to always find the active hosts in the network
    previous_tuples.append(["Searching for active hosts in the subnet..."])
    previous_tuples.append([""])

    return iface, previous_tuples

# Function to allow the user to input an ip address out of the {@code active_hosts} that is not in the {@code other_ips}
def validate_ip(active_hosts, other_ips, previous_tuples=[]):
    # assume the ip is not valid and get the user's input
    ip_is_valid = False
    curr_ip = inputf(previous_tuples)
    correct_tuple = {}

    # check if the input is an index in the list of active_hosts
    if curr_ip.strip().isdigit():
        curr_ip = int(curr_ip)
        if curr_ip > 0 and curr_ip < len(active_hosts) + 1:
            curr_ip = active_hosts[int(curr_ip) - 1]["ip"]

    # check if the input is one of the ips in the active_hosts
    for host in active_hosts:
        if (str(host["ip"]) == curr_ip):
            correct_tuple = host
            ip_is_valid = True
            break

    if (curr_ip in other_ips):
        # if the current ip is in the list of other_ip => it is invalid and procedure is repeated
        printf("Target repeated! Try again:", 2)
        return validate_ip(active_hosts, other_ips, previous_tuples)
    elif (ip_is_valid == True):
        # return the (ip, mac) tuple if the ip is valid
        return correct_tuple
    else:
        # otherwise the ip is invalid and pocedure is repeated
        printf("Invalid IP. Try again:", 2)
        return validate_ip(active_hosts, other_ips, previous_tuples)

# Function that prints correctly structured text for this tool.
# It should be used in stead of the base print function in python
# 
# @param text - text to be printed
# @param i - index that is used to style the output
# @param verbose - if True then printing does not occur
def printf(text, i=PRINT_INDEX, verbose=False):
    if not verbose:
        print(style_str(i) + str(text))
# Function used to get the user's input and allow for functionality such as closnig the program from anywhere
# 
# @param previous_tuples - list of text that should be displayed if the screen is cleared 
#                          and software should return to previously printed text
# @param eend - text that can be added before input of user but after the stylized header 
def inputf(previous_tuples=[], eend=""):

    # get the input of the user
    # where the input is preceded by a stylized header and optiojnal text after it
    _input = input(style_str(INPUT_INDEX) + eend)

    # if the user wants to exit the program
    if _input.lower() in ["q", "quit"]:
        # clear the screen and provide with a prompt for confirmation
        clear()
        printf("Are you sure you want to exit the application?", 1)
        if choice():
            # if user chose to exit => the process is killed
            sys.exit()
        else:
            # otherwise the user backed out so the previous_tuples should be dispalyed
            print_previous(previous_tuples, True)
            # get the user's input again
            _input = inputf(previous_tuples, eend)
    # if the user wants to go back to the beginning screen
    elif _input.lower() in ["r", "reset"]:
        # clear the screen and provide with a prompt for confirmation
        clear()
        printf("Are you sure you want to stop the current attack and return to the initial screen?", 1)
        if choice():
            # if user chose to reset => return to choosing an attack
            clear()
            choose_main_attack()
        else:
            # otherwise the user backed out so the previous_tuples should be dispalyed
            print_previous(previous_tuples, True)
            # get the user's input again
            _input = inputf(previous_tuples, eend)
    # if the user chose to display the help menu
    elif _input.lower() in ["h", "help"]:
        pass

    # return the input of the user
    return _input

# Helper function that allows the user to input yes or no to a previous request
#
# @return boolean value of the user's choice
def choice():
    # repeat the process until the user has made a choice
    while True:
        # get the user's input
        _inp = inputf().lower()
        # if the user chose 'yes' => return True
        if _inp in ["y", "yes", "ye"]:
            return True
        # if the user chose 'no' => return False
        elif _inp in ["n", "no"]:
            return False
        # otherwise make the user try again
        else:
            printf("Invalid Input. Try again!", 2)

# Function that plays a sound based on a relative address
def playsoundf(str, verbose=False):
    if not verbose:
        playsound(str)

# Function used to style a string for the header of each message printed by this tool
#
# @param i - the index used to style the header with further information
def style_str(i=PRINT_INDEX):
    # beggining of each message
    res = "|L&R| "

    # add a specific symbol based on the index i that is provided
    if i == -1:
        res += "[ ]" # Normal
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
        res += "[ ]" # Normal

    # return the stylized header
    return res + " "

# Function to print all element of the previous tuples
#
# @param previous_tuples - list of tuples to be printed
# @param clear_screen - if True => clear screen; otherwise => don't
def print_previous(previous_tuples, clear_screen=False):
    if clear_screen:
        clear()

    for _tuple in previous_tuples:
        try:
            # check if the tuple has a second argument and print it
            printf(_tuple[0], _tuple[1])
        except:
            # otherwise print the first argument only
            printf(_tuple[0])

# Function to clear the screen based on the OS of the system
def clear():
    # for windows
    if name == 'nt':
        _clear = system('cls')

    # for mac and linux
    else:
        _clear = system('clear')

# Function to alloww ip forwarding in the system
#
# @param should_forward - boolean value showing whether ip forwarding is enabled
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

# Function to handle the occurance of specific signal
def handler(signum, frame):
    choose_main_attack()

# Function that is called when the application is closed
def quit_sequence():
        playsoundf("resources/windows_xp_shutdown.mp3", verbose)
        printf("Closed: Lovec & Ribar.", 3)

# Call main function on first pass through file
if __name__=="__main__":
    # call handler if CTRL+Z occurs
    signal.signal(signal.SIGTSTP, handler)

    # call main
    try:
        main()
    except KeyboardInterrupt:
        # begin quit_sequence on KeyboardInterrupt
        print(" (KeyboardInterrupt)")
        quit_sequence()    
    except SystemExit:
        # begin quit_sequence on SystemExit
        print(" (SystemExit)")
        quit_sequence()
    except:
        # if another error occurs then print it and begin quit_sequence
        printf("Unexpected error!", 2)
        printf(sys.exc_info()[1], 2)
        printf("")
        quit_sequence()
    # main()