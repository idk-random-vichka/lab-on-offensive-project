    ip_mask = ""
    for i in range(len(bin_ip)):
        # use the bits from the ip until the mask has 1's
        if bin_netmask[i] == "1":
            ip_mask += bin_ip[i]
        else:
            break

    ip_mask += "_"+"0" * (len(bin_ip) - len(ip_mask))


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


from django.core.validators import URLValidator
from django.core.exceptions import ValidationError

val = URLValidator(verify_exists=False)
try:
    val('http://www.google.com')
except ValidationError, e:
    print e


    # spoof.printf("")
    # spoof.printf("Input the IP address of the server out of the active hosts("+str(1)+"-"+str(len(active_hosts))+"):", 1)
    # server = fpc.validate_ip(active_hosts, target["ip"])