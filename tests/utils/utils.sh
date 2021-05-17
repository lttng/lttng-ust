#!/bin/bash
#
# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (c) 2019 Michael Jeanson <mjeanson@efficios.com>
# Copyright (C) 2019 Philippe Proulx <pproulx@efficios.com>
#

# This file is meant to be sourced at the start of shell script-based tests.


# Error out when encountering an undefined variable
set -u

# If "readlink -f" is available, get a resolved absolute path to the
# tests source dir, otherwise make do with a relative path.
scriptdir="$(dirname "${BASH_SOURCE[0]}")"
if readlink -f "." >/dev/null 2>&1; then
	testsdir=$(readlink -f "$scriptdir/..")
else
	testsdir="$scriptdir/.."
fi

# Allow overriding the source and build directories
if [ "x${UST_TESTS_SRCDIR:-}" = "x" ]; then
	UST_TESTS_SRCDIR="$testsdir"
fi
export UST_TESTS_SRCDIR

if [ "x${UST_TESTS_BUILDDIR:-}" = "x" ]; then
	UST_TESTS_BUILDDIR="$testsdir"
fi
export UST_TESTS_BUILDDIR

# The OS on which we are running. See [1] for possible values of 'uname -s'.
# We do a bit of translation to ease our life down the road for comparison.
# Export it so that called executables can use it.
# [1] https://en.wikipedia.org/wiki/Uname#Examples
if [ "x${UST_OS_TYPE:-}" = "x" ]; then
	UST_OS_TYPE="$(uname -s)"
	case "$UST_OS_TYPE" in
	MINGW*)
		UST_OS_TYPE="mingw"
		;;
	Darwin)
		UST_OS_TYPE="darwin"
		;;
	Linux)
		UST_OS_TYPE="linux"
		;;
	CYGWIN*)
		UST_OS_TYPE="cygwin"
		;;
	FreeBSD)
		UST_OS_TYPE="freebsd"
		;;
	*)
		UST_OS_TYPE="unsupported"
		;;
	esac
fi
export UST_OS_TYPE

