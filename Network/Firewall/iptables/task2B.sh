#!/bin/bash

# Outside hosts cannot ping internal hosts.
iptables -A FORWARD -p icmp --icmp-type echo-request -i eth0 -j DROP

# Outside hosts can ping the router.
# (INPUT and OUTPUT chains are set to ACCEPT by default)

# Internal hosts can ping outside hosts.
iptables -A FORWARD -p icmp --icmp-type echo-request -i eth1 -j ACCEPT
iptables -A FORWARD -p icmp --icmp-type echo-reply -i eth0 -j ACCEPT

iptables -P FORWARD DROP