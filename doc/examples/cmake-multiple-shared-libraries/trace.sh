#!/bin/bash
#
# SPDX-License-Identifier: MIT

lttng create
lttng enable-event -u 'gydle_om:*'
lttng start
./tester
lttng stop
lttng view > trace.txt
cat trace.txt
