#!/bin/bash
# Written by Marco Bonetti & Mike Perry
# Based on instructions from Dan Singletary's ADSL Bandwidth Management HOWTO
# http://www.faqs.org/docs/Linux-HOWTO/ADSL-Bandwidth-Management-HOWTO.html
# This script is Public Domain.

# BEGIN USER TUNABLE PARAMETERS

DEV=eth0

# NOTE! You must START Tor under this UID. Using the Tor User/Group 
# config setting is NOT sufficient.
TOR_UID=$(id -u tor)

# If the UID mechanism doesn't work for you, you can set this parameter
# instead. If set, it will take precedence over the UID setting. Note that
# you need multiple IPs for this to work.
#TOR_IP="42.42.42.42"

# Average ping to most places on the net, milliseconds
RTT_LATENCY=40

# RATE_UP must be less than your connection's upload capacity. If it is
# larger, then the bottleneck will be at your router's queue, which you
# do not control. This will cause congestion and a revert to normal TCP
# fairness no matter what the queing priority is.
RATE_UP=5000

# RATE_UP_TOR is the minimum speed your Tor connections will have.
# They will have at least this much bandwidth for upload
RATE_UP_TOR=1500

# RATE_UP_TOR_CEIL is the maximum rate allowed for all Tor trafic
RATE_UP_TOR_CEIL=5000

CHAIN=OUTPUT
#CHAIN=PREROUTING
#CHAIN=POSTROUTING

MTU=1500
AVG_PKT=900

# END USER TUNABLE PARAMETERS

# The queue size should be no larger than your bandwidth-delay
# product. This is RT latency*bandwidth/MTU/2

BDP=$(expr $RTT_LATENCY \* $RATE_UP / $AVG_PKT)

# Further research indicates that the BDP calculations should use
# RTT/sqrt(n) where n is the expected number of active connections..

BDP=$(expr $BDP / 4)

if [ "$1" = "status" ]
then
	echo "[qdisc]"
	tc -s qdisc show dev $DEV
	tc -s qdisc show dev imq0
	echo "[class]"
	tc -s class show dev $DEV
	tc -s class show dev imq0
	echo "[filter]"
	tc -s filter show dev $DEV
	tc -s filter show dev imq0
	echo "[iptables]"
	iptables -t mangle -L TORSHAPER-OUT -v -x 2> /dev/null
	exit
fi


# Reset everything to a known state (cleared)
tc qdisc del dev $DEV root 2> /dev/null > /dev/null
tc qdisc del dev imq0 root 2> /dev/null > /dev/null
iptables -t mangle -D POSTROUTING -o $DEV -j TORSHAPER-OUT 2> /dev/null > /dev/null
iptables -t mangle -D PREROUTING -o $DEV -j TORSHAPER-OUT 2> /dev/null > /dev/null
iptables -t mangle -D OUTPUT -o $DEV -j TORSHAPER-OUT 2> /dev/null > /dev/null
iptables -t mangle -F TORSHAPER-OUT 2> /dev/null > /dev/null
iptables -t mangle -X TORSHAPER-OUT 2> /dev/null > /dev/null
ip link set imq0 down 2> /dev/null > /dev/null
rmmod imq 2> /dev/null > /dev/null

if [ "$1" = "stop" ]
then
	echo "Shaping removed on $DEV."
	exit
fi

# Outbound Shaping (limits total bandwidth to RATE_UP)

ip link set dev $DEV qlen $BDP

# Add HTB root qdisc, default is high prio
tc qdisc add dev $DEV root handle 1: htb default 20

# Add main rate limit class
tc class add dev $DEV parent 1: classid 1:1 htb rate ${RATE_UP}kbit

# Create the two classes, giving Tor at least RATE_UP_TOR kbit and capping
# total upstream at RATE_UP so the queue is under our control.
tc class add dev $DEV parent 1:1 classid 1:20 htb rate $(expr $RATE_UP - $RATE_UP_TOR)kbit ceil ${RATE_UP}kbit prio 0
tc class add dev $DEV parent 1:1 classid 1:21 htb rate $[$RATE_UP_TOR]kbit ceil ${RATE_UP_TOR_CEIL}kbit prio 10

# Start up pfifo
tc qdisc add dev $DEV parent 1:20 handle 20: pfifo limit $BDP
tc qdisc add dev $DEV parent 1:21 handle 21: pfifo limit $BDP

# filter traffic into classes by fwmark
tc filter add dev $DEV parent 1:0 prio 0 protocol ip handle 20 fw flowid 1:20
tc filter add dev $DEV parent 1:0 prio 0 protocol ip handle 21 fw flowid 1:21

# add TORSHAPER-OUT chain to the mangle table in iptables
iptables -t mangle -N TORSHAPER-OUT
iptables -t mangle -I $CHAIN -o $DEV -j TORSHAPER-OUT


# Set firewall marks
# Low priority to Tor
if [ ""$TOR_IP == "" ]
then
	echo "Using UID-based QoS. UID $TOR_UID marked as low priority."
	iptables -t mangle -A TORSHAPER-OUT -m owner --uid-owner $TOR_UID -j MARK --set-mark 21
else
	echo "Using IP-based QoS. $TOR_IP marked as low priority."
	iptables -t mangle -A TORSHAPER-OUT -s $TOR_IP -j MARK --set-mark 21
fi

# High prio for everything else
iptables -t mangle -A TORSHAPER-OUT -m mark --mark 0 -j MARK --set-mark 20

echo "Outbound shaping added to $DEV.  Rate for Tor upload at least: ${RATE_UP_TOR}Kbyte/sec."

