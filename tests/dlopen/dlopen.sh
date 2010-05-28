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

starttest "dlopen"

plan_tests 4

LD_LIBRARY_PATH=$TESTDIR/dlopen/.libs okx usttrace $TESTDIR/dlopen/dlopen
trace_loc=$(usttrace -W)
trace_matches -N "from_library" -n 1 "^ust.from_library:" $trace_loc
trace_matches -N "from_main_before_lib" -n 1 "^ust.from_main_before_lib:" $trace_loc
trace_matches -N "from_main_after_lib" -n 1 "^ust.from_main_after_lib:" $trace_loc
