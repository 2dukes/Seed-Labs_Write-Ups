#!/bin/bash

# All the internal hosts run a telnet server (listening to port 23). 
# Outside hosts can only access the telnet server on 192.168.60.5, not the other internal hosts.
iptables -A FORWARD -p tcp -i eth0 -d 192.168.60.5 --dport 23 -j ACCEPT
iptables -A FORWARD -p tcp -i eth1 -s 192.168.60.5 --sport 23 -j ACCEPT

# Outside hosts cannot access the other internal hosts.
iptables -A FORWARD -p tcp -i eth0 -j DROP

# Internal hosts can access all the internal servers.
# No need to do anything because these packets are not forwarded by the router but instead by the virtual switch sitting in the docker bridge.

# Internal hosts cannot access external servers.
iptables -A FORWARD -p tcp -i eth1 -j DROP

iptables -P FORWARD DROP