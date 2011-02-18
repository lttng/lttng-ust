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

TESTDIR=$(dirname $0)/..

source $TESTDIR/test_functions.sh
source $TESTDIR/tap.sh

starttest "fork()/exec() test"

plan_tests 8
USTTRACE="$TESTDIR/../usttrace"

okx $USTTRACE -L -f $TESTDIR/fork/.libs/fork $TESTDIR/fork/.libs/fork2
trace_loc=$($USTTRACE -W)
trace_matches -N "before_fork" "^ust.before_fork:" $trace_loc
trace_matches -N "after_fork_parent" "^ust.after_fork_parent:" $trace_loc
trace_matches -N "after_fork_child" "^ust.after_fork_child:" $trace_loc
trace_matches -N "before_exec" "^ust.before_exec:" $trace_loc
trace_matches -N "potential_exec" "^ust.potential_exec:" $trace_loc
trace_matches -N "after_exec" "^ust.after_exec:" $trace_loc
check_trace_logs "$trace_loc"
