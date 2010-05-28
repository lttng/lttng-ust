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

starttest "Test-nevents"

plan_tests 4

okx usttrace $TESTDIR/test-nevents/prog
trace_loc=$(usttrace -W)
trace_matches -N "an_event" -n 100000 "^ust.an_event:" $trace_loc
trace_matches -N "another_event" -n 100000 "^ust.another_event:" $trace_loc
check_trace_logs "$trace_loc"
