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

starttest "ustd valgrind check"

plan_tests 2

TRACE_DIR="/tmp/ust-testsuite-ustdvalgrind-trace"
rm -rf "$TRACE_DIR"
mkdir "$TRACE_DIR"

pidfilepath="/tmp/ust-testsuite-$USER-$(date +%Y%m%d%H%M%S%N)-ustd-pid"
mkfifo -m 0600 "$pidfilepath"

VALG_OUT=/tmp/ust-testsuite-valg.txt
valgrind -q ustd --pidfile "$pidfilepath" -o "$TRACE_DIR" >/dev/null 2>"$VALG_OUT" &
VALG_PID=$!
USTD_PID="$(<$pidfilepath)"

okx usttrace -s $TESTDIR/basic/.libs/basic

kill -SIGTERM $USTD_PID
wait $!

echo "Valgrind output is in $VALG_OUT"
if [ -z "$(<$VALG_OUT)" ]; then
    pass "Valgrind found no errors in ustd"
else
    fail "Valgrind found errors in ustd:"
    cat $VALG_OUT | while read; do
	diag $REPLY
    done
fi
