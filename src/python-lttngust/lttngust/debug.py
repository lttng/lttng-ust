# -*- coding: utf-8 -*-
#
# SPDX-License-Identifier: LGPL-2.1-only
#
# Copyright (C) 2015 Philippe Proulx <pproulx@efficios.com>

from __future__ import unicode_literals, print_function
import lttngust.compat
import time
import sys
import os


_ENABLE_DEBUG = os.getenv('LTTNG_UST_PYTHON_DEBUG', '0') == '1'


if _ENABLE_DEBUG:
    import inspect

    def _pwarning(msg):
        fname = inspect.stack()[1][3]
        fmt = '[{:.6f}] LTTng-UST warning: {}(): {}'
        print(fmt.format(lttngust.compat._clock(), fname, msg), file=sys.stderr)

    def _pdebug(msg):
        fname = inspect.stack()[1][3]
        fmt = '[{:.6f}] LTTng-UST debug: {}(): {}'
        print(fmt.format(lttngust.compat._clock(), fname, msg), file=sys.stderr)

    _pdebug('debug is enabled')
else:
    def _pwarning(msg):
        pass

    def _pdebug(msg):
        pass
