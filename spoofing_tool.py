from playsound import playsound # pip install
from scapy.all import *
from os import system, name
import netifaces as ni # pip install
import sys

import arp_spoofing as arp
import dns_spoofing as dns
import search_hosts as sh

INPUT_INDEX = 7
PRINT_INDEX = -1
default_iface = "lo"
verbose = True # mute outputs

# make 'q' work everywhere

def main():
    clear()
    printf("Welcome to our tool for spoofing!", 0)
    printf("")
    playsoundf("resources/windows_xp_startup.mp3", verbose)

    previous_tuples = [["Pick an attack: DNS(d) or ARP(a)", 1]]
    print_previous(previous_tuples)

    while True:
        _input = inputf(INPUT_INDEX, "", previous_tuples).lower()
        if _input in ["arp", "a"]:
            clear()
            printf("Chosen attack: ARP Poisoning.", 0)
            printf("-----------------------------")
            break
        elif _input in ["dns", "d"]:
            dns.dns_spoofing()
            break
        else:
            printf("Invalid Input. Try again!", 2)

def printf(text, i=PRINT_INDEX, verbose=False):
    if not verbose:
        print(style_str(i) + str(text))

def inputf(i=INPUT_INDEX, eend="", previous_tuples=[]):
    _input = input(style_str(i) + eend)
    if _input.lower() in ["q", "quit", "exit"]:
        clear()
        printf("Are you sure you want to exit the application?", 1)
        if choice():
            sys.exit()
        else:
            print_previous(previous_tuples, True)
            _input = inputf(i, eend, previous_tuples)

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
   
def quit_sequence():
        printf("Lovec & Ribar closed successfully.", 3)
        playsoundf("resources/windows_xp_shutdown.mp3", verbose)

# call main
if __name__=="__main__":
    # try:
    #     main()
    # except KeyboardInterrupt:
    #     print(" (KeyboardInterrupt)")
    #     quit_sequence()
    # except:
    #     quit_sequence()
    main()