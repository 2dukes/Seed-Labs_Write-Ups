#!/bin/bash

# All the internal hosts run a telnet server (listening to port 23). 
# Outside hosts can only access the telnet server on 192.168.60.5, not the other internal hosts.
iptables -A FORWARD -p tcp -i eth0 -d 192.168.60.5 --dport 23 \
    -m conntrack --ctstate NEW,ESTABLISHED,RELATED -j ACCEPT
iptables -A FORWARD -p tcp -i eth1 -s 192.168.60.5 --sport 23 \
    -m conntrack --ctstate NEW,ESTABLISHED,RELATED -j ACCEPT

# Internal hosts can access all the internal servers.
# No need to do anything because these packets are not forwarded by the router but instead by the virtual switch sitting in the docker bridge.

# Internal hosts CAN access external servers.
iptables -A FORWARD -p tcp -i eth1 --dport 23 \
    -m conntrack --ctstate NEW,ESTABLISHED,RELATED -j ACCEPT
iptables -A FORWARD -p tcp -i eth0 --sport 23 \
    -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# Outside hosts cannot access the other internal hosts.
iptables -A FORWARD -p tcp -i eth0 --dport 23 -m conntrack --ctstate NEW -j DROP

iptables -P FORWARD DROP

# Observations:
# Using the connection tracking mechanism makes the firewall stateful, so the performance when parsing the packets will be lower.
# The good thing is we can have a more detailed rule specification. 
# The approach without the connection tracking is faster, but we can''t detail if the connection was already established or not so, we have to generalize.
