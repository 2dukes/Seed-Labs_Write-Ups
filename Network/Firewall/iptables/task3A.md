# Experiment with the Connection Tracking

- **ICMP Experiment** - From `10.9.0.5`, ping `192.168.60.5` and check for how long the router keeps the connection state.

***Answer:*** 30 seconds.

```
root@b54abb71a404:/volumes/iptables# conntrack -L
icmp     1 30 src=10.9.0.5 dst=192.168.60.5 type=8 code=0 id=31 src=192.168.60.5 dst=10.9.0.5 type=0 code=0 id=31 mark=0 use=1
conntrack v1.4.5 (conntrack-tools): 1 flow entries have been shown.
```

- **UDP Experiment** 

***Answer:*** 30 seconds.

```
root@b54abb71a404:/volumes/iptables# conntrack -L
udp      17 29 src=10.9.0.5 dst=192.168.60.5 sport=37128 dport=9090 [UNREPLIED] src=192.168.60.5 dst=10.9.0.5 sport=9090 dport=37128 mark=0 use=1
conntrack v1.4.5 (conntrack-tools): 1 flow entries have been shown.
```

- **TCP Experiment** 

***Answer:*** 432000 seconds.

```
root@b54abb71a404:/volumes/iptables# conntrack -L
tcp      6 431997 ESTABLISHED src=10.9.0.5 dst=192.168.60.5 sport=60388 dport=9090 src=192.168.60.5 dst=10.9.0.5 sport=9090 dport=60388 [ASSURED] mark=0 use=1
conntrack v1.4.5 (conntrack-tools): 1 flow entries have been shown.
```

After finishing the connection, 120 seconds of `TIME_WAIT`.

```
root@b54abb71a404:/volumes/iptables# conntrack -L
tcp      6 117 TIME_WAIT src=10.9.0.5 dst=192.168.60.5 sport=60388 dport=9090 src=192.168.60.5 dst=10.9.0.5 sport=9090 dport=60388 [ASSURED] mark=0 use=1
conntrack v1.4.5 (conntrack-tools): 1 flow entries have been shown.
```