#!/usr/bin/env bash

# The Query Interval is the interval between General Queries sent by
# the Querier. Default: 125 seconds.
#
# By varying the [Query Interval], an administrator may tune the number
# of IGMP messages on the network; larger values cause IGMP Queries to
# be sent less often.

$(dirname $0)/configure-router.sh "QUERY_INTERVAL $1"