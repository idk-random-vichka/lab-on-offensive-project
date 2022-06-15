from scapy.all import *
import netifaces as ni
import arp_spoofing as arp
import search_hosts as sh
import sys, os
from playsound import playsound

default_iface = "lo"

def main():
    printf("Welcome to our tool for spoofing!")
    playsound("resources/windows_xp_startup.mp3")

    printf("Choose an attack: dns or arp", 1)
    while True:
        _input = inp("Choose an attack: dns or arp", 1).lower()
        if _input in ["arp", "a"]:
            printf("Chosen attack: ARP Poisoning.")
            break
        elif _input in ["dns", "d"]:
            printf("Chosen attack: DNS Spoofing.")
            break
        else:
            printf("Invalid Input. Try again!", 2)
        

def inp(title = "", i=-1):
    _input = inputf().lower()
    if _input in ["q", "quit", "exit"]:
        printf("Are you sure you want to exit the application?", 0)
        if choice():
            sys.exit()
        else:
            printf(title, i)
            _input = inp(title).lower()

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

def printf(str, i=-1, verbose=False):
    if not verbose:
        print(style_str(i) + str)

def inputf(i=-1):
    return input(style_str(i))

def style_str(i = -1):
    res = "|L&R| "

    if i == 0:
        res += "[!]"
    elif i == 1:
        res += "[?]"
    elif i == 2:
        res += "[I]"
    elif i == 3:
        res += "[X]"
    else:
        res += "[ ]"

    return res + " "


# call main
if __name__=="__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(" KeyboardInterrupt")
        printf("Lovec & Ribar closed successfully.", 3)
        playsound("resources/windows_xp_shutdown.mp3")
    except:
        printf("Lovec & Ribar closed successfully.", 3)
        playsound("resources/windows_xp_shutdown.mp3")