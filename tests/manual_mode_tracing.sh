#!/bin/bash
#
# Copyright 2010 Ericsson AB
#
#    This file is part of LTTng-UST.
#
#    LTTng-UST is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    LTTng-UST is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with LTTng-UST.  If not, see <http://www.gnu.org/licenses/>.

# This tests manual mode tracing, meaning the process is first started, then
# the tracing is set up with ustctl. Then verifications are done to make sure
# all the events that were supposed to be in the trace are there.

TESTDIR=$(dirname $0)

source $TESTDIR/test_functions.sh
source $TESTDIR/tap.sh

starttest "Manual mode tracing"

plan_tests 9

TRACE_DIR="/tmp/ust-testsuite-manual-trace"
rm -rf "$TRACE_DIR"
mkdir "$TRACE_DIR"

pidfilepath="/tmp/ust-testsuite-$USER-$(date +%Y%m%d%H%M%S%N)-ust-consumerd-pid"
mkfifo -m 0600 "$pidfilepath"

ust-consumerd --pidfile "$pidfilepath" -o "$TRACE_DIR" >/dev/null 2>&1 &
UST_CONSUMERD_PID="$(<$pidfilepath)"

LD_PRELOAD=/usr/local/lib/libust.so.0.0.0:/usr/local/lib/libustinstr-malloc.so find -L / >/dev/null 2>&1 &
PID=$!
TRACE=auto
sleep 0.1
okx ustctl list-markers $PID
okx ustctl enable-marker $PID $TRACE ust/malloc
okx ustctl enable-marker $PID $TRACE ust/free
okx ustctl create-trace $PID $TRACE
okx ustctl alloc-trace $PID $TRACE
okx ustctl start-trace $PID $TRACE
sleep 0.5

okx ustctl stop-trace $PID $TRACE
okx ustctl destroy-trace $PID $TRACE
kill $PID
kill -SIGTERM ${UST_CONSUMERD_PID}
wait ${UST_CONSUMERD_PID}

trace_matches -N "ust.malloc" "^ust.malloc:" "$TRACE_DIR"
