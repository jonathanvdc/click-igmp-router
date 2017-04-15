#!/usr/bin/env bash

timeout 240 ./click-2.0.1/userlevel/click -p 10000 scripts/ipnetwork.click &
sleep 5
./join.sh client31
./join.sh client22
# Set client31's robustness to four.
./set-robustness.sh client31 4
# Set client31's unsolicited report interval to 0.5 seconds.
./set-client-uri.sh client32 5
sleep 5
./join.sh client21
./join.sh client32
sleep 5
# Should not do anything.
./join.sh client31
./join.sh client31
sleep 5
# Make sure that leave/join in rapid succession actually work.
./leave.sh client21
./join.sh client21
./leave.sh client21
sleep 5
# Have all clients except client32 leave the group.
./leave.sh client21
./leave.sh client22
./leave.sh client31
sleep 5
# Now wait to make sure that the router keeps on forwarding messages to client32.
wait