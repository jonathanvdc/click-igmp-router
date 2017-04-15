#!/usr/bin/env bash

# The Last Member Query Count is the number of Group-Specific Queries
# sent before the router assumes there are no local members. The Last
# Member Query Count is also the number of Group-and-Source-Specific
# Queries sent before the router assumes there are no listeners for a
# particular source. Default: the Robustness Variable.

$(dirname $0)/configure-router.sh "LAST_MEMBER_QUERY_COUNT $1"