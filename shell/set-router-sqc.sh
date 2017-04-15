#!/usr/bin/env bash

# The Startup Query Count is the number of Queries sent out on startup,
# separated by the Startup Query Interval. Default: the Robustness
# Variable.

$(dirname $0)/config-router.sh "STARTUP_QUERY_COUNT $1"