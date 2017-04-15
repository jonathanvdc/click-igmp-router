#!/usr/bin/env bash

echo "write $1/igmp/igmp.config UNSOLICITED_REPORT_INTERVAL $2" | telnet localhost 10000