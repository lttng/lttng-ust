# -*- coding: utf-8 -*-
#
# Copyright (C) 2020 - Jonathan Rajotte <jonathan.rajotte-julien@efficios.com>
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

import sys
import time


# Support for deprecation of time.clock().
# Deprecated since python 3.3 and removed in python 3.8.
# See PEP 418 for more details.
def _clock():
    if sys.version_info > (3,2):
        clock = time.perf_counter()
    else:
        clock = time.clock()
    return clock
