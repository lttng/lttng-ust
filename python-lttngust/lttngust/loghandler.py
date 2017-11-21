# -*- coding: utf-8 -*-
#
# Copyright (C) 2015 - Philippe Proulx <pproulx@efficios.com>
# Copyright (C) 2014 - David Goulet <dgoulet@efficios.com>
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

from __future__ import unicode_literals
import logging
import ctypes


class _Handler(logging.Handler):
    _LIB_NAME = 'liblttng-ust-python-agent.so.0'

    def __init__(self):
        super(self.__class__, self).__init__(level=logging.NOTSET)
        self.setFormatter(logging.Formatter('%(asctime)s'))

        # will raise if library is not found: caller should catch
        self.agent_lib = ctypes.cdll.LoadLibrary(_Handler._LIB_NAME)

    def emit(self, record):
        self.agent_lib.py_tracepoint(self.format(record).encode(),
                                     record.getMessage().encode(),
                                     record.name.encode(),
                                     record.funcName.encode(),
                                     record.lineno, record.levelno,
                                     record.thread,
                                     record.threadName.encode())
