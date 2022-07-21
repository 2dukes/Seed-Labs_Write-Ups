from scapy.all import *

def print_pkt(pkt):
    pkt.show()

pkt = sniff(iface='br-6cf438e5ef95', filter='icmp', prn=print_pkt)
# pkt = sniff(iface='br-6cf438e5ef95', filter='src host 10.9.0.5 and dst port 23 and tcp', prn=print_pkt)
# pkt = sniff(iface='br-6cf438e5ef95', filter='net 128.230.0.0/16', prn=print_pkt)
