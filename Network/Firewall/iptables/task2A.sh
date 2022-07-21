#!/bin/bash

iptables -A INPUT -p icmp --icmp-type echo-request -j ACCEPT
iptables -A OUTPUT -p icmp --icmp-type echo-reply -j ACCEPT
iptables -P OUTPUT DROP
iptables -P INPUT DROP

# Questions
# 1 - Can you ping the router?
# Yes, because there are specific rules to allow ICMP traffic tha have grater priority than the set policies.
# 2 - Can you telnet into the router?
# No, because the policies (INPUT and OUTPUT) are set to DROP by default.
