#!/usr/bin/env bash

# The Startup Query Interval is the interval between General Queries
# sent by a Querier on startup. Default: 1/4 the Query Interval.

$(dirname $0)/configure-router.sh "STARTUP_QUERY_INTERVAL $1"