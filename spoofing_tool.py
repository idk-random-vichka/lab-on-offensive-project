from scapy.all import *
import netifaces as ni # pip install
import sys, os
from playsound import playsound # pip install

import arp_spoofing as arp
import dns_spoofing as dns
import search_hosts as sh

default_iface = "lo"

def main():
    printf("Welcome to our tool for spoofing!")
    printf("")
    playsoundf("resources/windows_xp_startup.mp3", True)

    choose_atk_str = "Pick an attack: DNS(d) or ARP(a)"
    printf(choose_atk_str, 1)
    while True:
        _input = inp(choose_atk_str, 1, 7).lower()
        if _input in ["arp", "a"]:
            printf("")
            printf("Chosen attack: ARP Poisoning.")
            printf("-----------------------------")
            break
        elif _input in ["dns", "d"]:
            printf("")
            printf("Chosen attack: DNS Spoofing.")
            printf("----------------------------")
            dns.dns_spoofing()
            break
        else:
            printf("Invalid Input. Try again!", 2)
        

def inp(title = "", p=-1, i=-1):
    _input = inputf(i).lower()
    if _input in ["q", "quit", "exit"]:
        printf("Are you sure you want to exit the application?", 2)
        if choice(i):
            sys.exit()
        else:
            printf(title, p)
            _input = inp(title, p, i).lower()

    return _input

def choice(i=-1):
    while True:
        _inp = inputf(i).lower()
        if _inp in ["y", "yes", "ye"]:
            return True
        elif _inp in ["n", "no"]:
            return False
        else:
            printf("Invalid Input. Try again!", 2)

def printf(str, i=-1, verbose=False):
    if not verbose:
        print(style_str(i) + str)

def inputf(i=-1):
    return input(style_str(i))

def playsoundf(str, verbose=False):
    if not verbose:
        playsound(str)

def style_str(i = -1):
    res = "|L&R| "

    if i == 0:
        res += "[x]" # ~Warning
    elif i == 1:
        res += "[?]" # Question
    elif i == 2:
        res += "[!]" # Invalid input / Warning
    elif i == 3:
        res += "[X]" # Closing application
    elif i == 4:
        res += "[.]" 
    elif i == 5:
        res += "[M]" 
    elif i == 6:
        res += "[=]" 
    elif i == 7:
        res += "[>]" # Input
    else:
        res += "[ ]"

    return res + " "

def quit_sequence():
        printf("Lovec & Ribar closed successfully.", 3)
        playsoundf("resources/windows_xp_shutdown.mp3", True)

# call main
if __name__=="__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(" (KeyboardInterrupt)")
        quit_sequence()
    except:
        quit_sequence()