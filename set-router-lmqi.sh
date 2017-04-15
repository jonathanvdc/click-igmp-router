#!/usr/bin/env bash

# The Last Member Query Interval is the Max Response Time used to
# calculate the Max Resp Code inserted into Group-Specific Queries sent
# in response to Leave Group messages. It is also the Max Response
# Time used in calculating the Max Resp Code for Group-and-Source-
# Specific Query messages. Default: 10 (1 second)
#
# This value may be tuned to modify the "leave latency" of the network.
# A reduced value results in reduced time to detect the loss of the
# last member of a group or source.

./configure-router.sh "LAST_MEMBER_QUERY_INTERVAL $1"