    # import subprocess
    # subprocess.call(["sysctl", "-w", "net.ipv4.ip_forward=1"])
    
    
    #network_ips = list(network_addr.hosts()) # list of the usable hosts in the network (excluding the network address & broadcast address)

    #arp.one_way_arp(g_macT1, g_ipT1, dns_ip, g_macAtk, g_ipAtk, iface) 
    #print(sniff.__doc__)
    #gateway_ip = conf.route.route(sh.get_my_details(iface)["ip"])[2]
    #print(gateway_ip)
    #pkt = build_packet()
    #sendp(pkt, iface=iface)

    #def one_way_arp(macT1, ipT1, ipT2, macAtk, ipAtk, iface):
    #    macT2 = ONE_WAY_TOKEN
    #    poison_m_times_every_n_secs(middle_count, middle_interval, time.clock(), True, macT1, ipT1, macT2, ipT2, macAtk, ipAtk, iface)

            # my_details = sh.get_my_details(iface)
        # #pkt[Ether].dst = "ff:ff:ff:ff:ff:ff"
        # pkt[Ether].src = my_details["mac"]
        # pkt[IP].src = my_details["ip"]

        # del pkt[IP].len
        # del pkt[IP].chksum
        # del pkt[UDP].len
        # del pkt[UDP].chksum

        # pkt = pkt.__class__(str(pkt))
        # print(pkt.show())
        # new_pkt = sr(pkt)
        # print(new_pkt.show())
        # x = input()

# old dns variables
# dns_hosts = {
#     b"belot.bg.": "some ip idk",
#     b"lacorte.co.kr.": "some ip idk",
#     b"twitch.tv.": "some ip idk",
# }

# # M1 details
# g_macT1 = "08:00:27:69:30:02"
# g_ipT1 = "10.0.2.4"

# # M2 details
# g_macT2 = "08:00:27:01:66:92"
# g_ipT2 = "10.0.2.6"

# # attacker(M3) details
# g_macAtk = "08:00:27:b1:e2:2c"            
# g_ipAtk = "10.0.2.5"

# iface = "enp0s9"
# dns_ip  = "131.155.2.3"
# dns_ip2 = "131.155.3.3"
# dns_ip3 = "10.0.2.1"

# inside dns main function 
    # arp.one_way_arp_start(g_macT1, g_ipT1, dns_ip, my_addresses['mac'], my_addresses['ip'], iface)
    # arp.one_way_arp_start(g_macT1, g_ipT1, dns_ip2, my_addresses['mac'], my_addresses['ip'], iface)

# inside dns repoison function
    #arp.one_way_arp(g_macT1, g_ipT1, dns_ip, my_addresses['mac'], my_addresses['ip'], iface, 2)
    #arp.one_way_arp(g_macT1, g_ipT1, dns_ip2, my_addresses['mac'], my_addresses['ip'], iface, 2)


# from django.core.validators import URLValidator
# from django.core.exceptions import ValidationError

# val = URLValidator(verify_exists=False)
# try:
#     val('http://www.google.com')
# except ValidationError, e:
#     print e


# spoof.printf("")
# spoof.printf("Input the IP address of the server out of the active hosts("+str(1)+"-"+str(len(active_hosts))+"):", 1)
# server = fpc.validate_ip(active_hosts, target["ip"])


# dns_hosts = {
#     b"belot.bg.": "10.0.2.6",
# }

# target_ip = "10.0.2.4" M1
# ip_to_spoof = "10.0.2.6" M2k


        # else:
        #     # spoof.should_ip_forward(True)
        #     if pkt[IP].dst == "131.155.2.3":
        #         print("miilk")
        #         pkt[Ether].dst = "ff:ff:ff:ff:ff:ff"
        #         try:
        #             del pkt[IP].len
        #             del pkt[IP].chksum
        #         except:
        #             pass

        #         try:
        #             del pkt[UDP].len
        #             del pkt[UDP].chksum
        #         except:
        #             pass

        #         new_pkt = send(pkt, iface=iface)
            # time.sleep(0.1)
            # spoof.should_ip_forward(False)

        # elif pkt.haslayer(DNS) and pkt[IP].src == target['ip']:

        #     pkt[Ether].dst = "ff:ff:ff:ff:ff:ff"
        #     pkt[Ether].src = my_addresses['mac']

        #     pkt[IP].src = my_addresses['ip']

        #     del pkt[IP].len
        #     del pkt[IP].chksum

        #     del pkt[UDP].len
        #     del pkt[UDP].chksum

        #     new_pkt = sr1(pkt, iface=iface)
        #     print(new_pkt.show())


## CONSTANTS ##
START_COUNT = 5 # ettercap starts poisoning with 5 packets
MIDDLE_COUNT = 200 #sys.maxint # ettercap keeps poisoning for 200 packets
END_COUNT = 3 # ettercap ends poisoning with 3 packets

START_INTERVAL = 1 # ettercap sends packets every second
MIDDLE_INTERVAL = 20 # ettercap sends packets every 10 seconds
END_INTERVAL = 1 # ettercap sends packets every second

ONE_WAY_TOKEN = "__ONE_WAY_TOKEN__"

                # sendpfast(pkt, iface=iface)

                # try:
                #     # new_pkt = srp1(pkt, verbose=0, iface=iface, timeout=2)[0]
                #     # # if pkt.haslayer(DNS):
                #     # # else:
                #     # #     new_pkt = sr1(pkt, iface=iface)[0]

                #     # new_pkt[Ether].dst = target["mac"]

                #     # if new_pkt.haslayer(IP):
                #     #     del new_pkt[IP].len
                #     #     del new_pkt[IP].chksum
                    
                #     # if new_pkt.haslayer(UDP):
                #     #     del new_pkt[UDP].len
                #     #     del new_pkt[UDP].chksum

                #     #sendp(pkt, count=1, iface=iface)
                #     s2.sendp(pkt, count=1)
                # except:
                #     pass