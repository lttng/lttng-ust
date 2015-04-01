# -*- coding: utf-8 -*-
#
# Copyright (C) 2015 - Philippe Proulx <pproulx@efficios.com>
#
# This library is free software; you can redistribute it and/or modify it under
# the terms of the GNU Lesser General Public License as published by the Free
# Software Foundation; version 2.1 of the License.
#
# This library is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more
# details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with this library; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301 USA

from __future__ import unicode_literals, print_function
import time
import sys
import os


_ENABLE_DEBUG = os.getenv('LTTNG_UST_PYTHON_DEBUG', '0') == '1'


if _ENABLE_DEBUG:
    import inspect

    def _pwarning(msg):
        fname = inspect.stack()[1][3]
        fmt = '[{:.6f}] LTTng-UST warning: {}(): {}'
        print(fmt.format(time.clock(), fname, msg), file=sys.stderr)

    def _pdebug(msg):
        fname = inspect.stack()[1][3]
        fmt = '[{:.6f}] LTTng-UST debug: {}(): {}'
        print(fmt.format(time.clock(), fname, msg), file=sys.stderr)

    _pdebug('debug is enabled')
else:
    def _pwarning(msg):
        pass

    def _pdebug(msg):
        pass
