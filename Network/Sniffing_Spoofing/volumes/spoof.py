from scapy.all import *

a = IP()
a.dst = '10.9.0.6'
b = ICMP()
p = a/b
send(p)