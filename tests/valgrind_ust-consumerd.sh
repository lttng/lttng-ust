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

starttest "ust-consumerd valgrind check"

if ! which valgrind > /dev/null; then
    echo "$0: Valgrind not found on the system." 1>&2
    exit 1;
fi

plan_tests 2

TRACE_DIR="/tmp/ust-testsuite-$USER-ust-consumerdvalgrind-trace"
rm -rf "$TRACE_DIR"
mkdir "$TRACE_DIR"

pidfilepath="/tmp/ust-testsuite-$USER-$(date +%Y%m%d%H%M%S%N)-ust-consumerd-pid"
mkfifo -m 0600 "$pidfilepath"

UST_CONSUMERD="$TESTDIR/../ust-consumerd/.libs/ust-consumerd"
USTTRACE="$TESTDIR/../usttrace"

VALG_OUT=/tmp/ust-testsuite-$USER-valg.txt
export LD_LIBRARY_PATH="$LD_LIBRARY_PATH:$TESTDIR/../libustconsumer/.libs/"
valgrind --suppressions=$TESTDIR/valgrind_suppress.txt -q $UST_CONSUMERD --pidfile "$pidfilepath" -o "$TRACE_DIR" >/dev/null 2>"$VALG_OUT" &
VALG_PID=$!

# Paranoid check that valgrind is alive or we will hang forever on the fifo
if ! ps $VALG_PID > /dev/null; then
    echo "Valgrind appears to have died, giving up"
    rm $pidfilepath
    exit
fi

UST_CONSUMERD_PID="$(<$pidfilepath)"

okx $USTTRACE -L -s $TESTDIR/basic/.libs/basic

kill -SIGTERM ${UST_CONSUMERD_PID}
wait $!

echo "Valgrind output is in $VALG_OUT"
if [ -z "$(<$VALG_OUT)" ]; then
    pass "Valgrind found no errors in ust-consumerd"
else
    fail "Valgrind found errors in ust-consumerd:"
    cat $VALG_OUT | while read; do
	diag "$REPLY"
    done
fi

rm $pidfilepath
