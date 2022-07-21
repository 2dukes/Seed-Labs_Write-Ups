#!/bin/bash

iptables -t nat -A PREROUTING -p udp --dport 8080 \
    -m statistic --mode nth --every 3 --packet 0 \
    -j DNAT --to-destination 192.168.60.5:8080

# Observations (with the first rule only):
# One for every three packets will go through the router to the 192.168.60.5 machine.

# Note the flag --packet on the 3 rules, except for the last one.

iptables -t nat -A PREROUTING -p udp --dport 8080 \
    -m statistic --mode nth --every 2 --packet 0 \
    -j DNAT --to-destination 192.168.60.6:8080

iptables -t nat -A PREROUTING -p udp --dport 8080 \
    -j DNAT --to-destination 192.168.60.7:8080