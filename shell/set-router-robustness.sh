#!/usr/bin/env bash

# The Robustness Variable allows tuning for the expected packet loss on
# a network. If a network is expected to be lossy, the Robustness
# Variable may be increased. IGMP is robust to (Robustness Variable -
# 1) packet losses. The Robustness Variable MUST NOT be zero, and
# SHOULD NOT be one. Default: 2

$(dirname $0)/configure-router.sh "ROBUSTNESS $1"