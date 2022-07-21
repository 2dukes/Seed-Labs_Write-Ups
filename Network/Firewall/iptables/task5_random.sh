#!/bin/bash

iptables -t nat -A PREROUTING -p udp --dport 8080 \
    -m statistic --mode random --probability 0.33 \
    -j DNAT --to-destination 192.168.60.5:8080

# Observations:
# Notice that 3 different probabilities are defined. This is because the rules are executed sequentially.
# With a p = 0.33, the first rule will beexecuted 33% of the time and skipped 66% of the time.
# With a probability of 0.5, the second rule will be executed 50% of the time and skipped 50% of the time. 
# However, since this rule is placed after the first one, it will only be executed 66% of the time.
# Hence this rule will be applied to only 50% * 60% = 33% of the requests.
# Since only 33% of the traffic reaches the last rule, it must always be applied.

iptables -t nat -A PREROUTING -p udp --dport 8080 \
    -m statistic --mode random --probability 0.5 \
    -j DNAT --to-destination 192.168.60.6:8080

iptables -t nat -A PREROUTING -p udp --dport 8080 \
    -j DNAT --to-destination 192.168.60.7:8080