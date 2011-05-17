#!/bin/bash
#
# Copyright 2011 Ericsson AB
#
#    This file is part of the UST test-suite.
#
#    The UST test-suite is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 2 of the License, or
#    (at your option) any later version.
#
#    The UST test-suite is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with the UST test-suite.  If not, see <http://www.gnu.org/licenses/>.

TESTDIR=$(dirname $0)/..

source $TESTDIR/test_functions.sh
source $TESTDIR/tap.sh

starttest "Exit-Fast"

plan_tests 6
USTTRACE="$TESTDIR/../usttrace"

diag "#"
diag "First run, normal exit"
diag "#"

okx $USTTRACE -L $TESTDIR/exit-fast/exit-fast
trace_loc=$($USTTRACE -W)
trace_matches -N "fast" -n 1 "^ust.fast:" $trace_loc
check_trace_logs "$trace_loc"

diag "#"
diag "Re-running, killing process"
diag "#"

okx $USTTRACE -L $TESTDIR/exit-fast/exit-fast suicide
trace_loc=$($USTTRACE -W)
trace_matches -N "fast" -n 1 "^ust.fast:" $trace_loc
check_trace_logs "$trace_loc"
