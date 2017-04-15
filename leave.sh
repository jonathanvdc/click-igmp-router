#!/usr/bin/env bash

echo "write $1/igmp/igmp.leave GROUP 224.1.0.20" | telnet localhost 10000