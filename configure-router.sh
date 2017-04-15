#!/usr/bin/env bash

echo "write router/igmp_multicast_server/igmp.config $@" | telnet localhost 10000
echo "write router/igmp_client1/igmp.config $@" | telnet localhost 10000
echo "write router/igmp_client2/igmp.config $@" | telnet localhost 10000