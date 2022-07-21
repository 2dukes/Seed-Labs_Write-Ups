from scapy.all import *

a = IP()
a.dst = '8.8.8.8'
b = ICMP()

print("\n********** TRACEROUTE ***********\n")

for i in range(1, 100):
    a.ttl = i
    ans, unans = sr(a/b, verbose=0)

    for snd, rcv in ans:
        is_reply = rcv.sprintf("{ICMP:%ICMP.type%}") == "echo-reply"
        print(rcv.sprintf("%IP.src%\t{ICMP:%ICMP.type%}\t{TCP:%TCP.flags%}"))

    if is_reply:
        break