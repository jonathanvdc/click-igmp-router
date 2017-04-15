#!/usr/bin/env bash

# The Max Response Time used to calculate the Max Resp Code inserted
# into the periodic General Queries. Default: 100 (10 seconds)
#
# By varying the [Query Response Interval], an administrator may tune
# the burstiness of IGMP messages on the network; larger values make
# the traffic less bursty, as host responses are spread out over a
# larger interval. The number of seconds represented by the [Query
# Response Interval] must be less than the [Query Interval].

$(dirname $0)/configure-router.sh "QUERY_RESPONSE_INTERVAL $1"