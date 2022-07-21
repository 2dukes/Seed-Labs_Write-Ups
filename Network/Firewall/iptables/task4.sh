#!/bin/bash

iptables -A FORWARD -s 10.9.0.5 -m limit \
    --limit 10/minute --limit-burst 5 -j ACCEPT

iptables -A FORWARD -s 10.9.0.5 -j DROP

# Observations:
# What happens when we, from 10.9.0.5 ping the IP 192.168.60.5
# get an average of 10 ping packets per second.