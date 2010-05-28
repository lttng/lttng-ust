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

TESTDIR=$(dirname $0)

source $TESTDIR/test_functions.sh
source $TESTDIR/tap.sh

starttest "Manual mode tracing"

plan_tests 9

TRACE_DIR="/tmp/ust-testsuite-manual-trace"
rm -rf "$TRACE_DIR"
mkdir "$TRACE_DIR"

pidfilepath="/tmp/ust-testsuite-$USER-$(date +%Y%m%d%H%M%S%N)-ustd-pid"
mkfifo -m 0600 "$pidfilepath"

ustd --pidfile "$pidfilepath" -o "$TRACE_DIR" >/dev/null 2>&1 &
USTD_PID="$(<$pidfilepath)"

LD_PRELOAD=/usr/local/lib/libust.so.0.0.0:/usr/local/lib/libustinstr-malloc.so find -L / >/dev/null 2>&1 &
PID=$!
sleep 0.1
okx ustctl --list-markers "$PID"
okx ustctl --enable-marker ust/malloc $PID
okx ustctl --enable-marker ust/free $PID
okx ustctl --create-trace $PID
okx ustctl --alloc-trace $PID
okx ustctl --start-trace $PID
sleep 0.5

okx ustctl --stop-trace $PID
okx ustctl --destroy-trace $PID
kill $PID
kill -SIGTERM $USTD_PID
wait $USTD_PID

trace_matches -N "ust.malloc" "^ust.malloc:" "$TRACE_DIR"
