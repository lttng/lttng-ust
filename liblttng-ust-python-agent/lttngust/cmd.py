# -*- coding: utf-8 -*-
#
# Copyright (C) 2015 - Philippe Proulx <pproulx@efficios.com>
# Copyright (C) 2014 - David Goulet <dgoulet@efficios.com>
# Copyright (C) 2015 - Jérémie Galarneau <jeremie.galarneau@efficios.com>
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
import lttngust.debug as dbg
import struct


# server command header
_server_cmd_header_struct = struct.Struct('>QII')


# server command header size
_SERVER_CMD_HEADER_SIZE = _server_cmd_header_struct.size


# agent protocol symbol size
_LTTNG_SYMBOL_NAME_LEN = 256


class _ServerCmdHeader(object):
    def __init__(self, data_size, cmd_id, cmd_version):
        self.data_size = data_size
        self.cmd_id = cmd_id
        self.cmd_version = cmd_version


def _server_cmd_header_from_data(data):
    try:
        data_size, cmd_id, cmd_version = _server_cmd_header_struct.unpack(data)
    except (Exception) as e:
        dbg._pdebug('cannot decode command header: {}'.format(e))
        return None

    return _ServerCmdHeader(data_size, cmd_id, cmd_version)


class _ServerCmd(object):
    def __init__(self, header):
        self.header = header

    @classmethod
    def from_data(cls, header, data):
        raise NotImplementedError()


class _ServerCmdList(_ServerCmd):
    @classmethod
    def from_data(cls, header, data):
        return cls(header)


class _ServerCmdEnable(_ServerCmd):
    _NAME_OFFSET = 8
    _loglevel_struct = struct.Struct('>II')
    # filter expression size
    _filter_exp_len_struct = struct.Struct('>I')

    def __init__(self, header, loglevel, loglevel_type, name, filter_exp):
        super(self.__class__, self).__init__(header)
        self.loglevel = loglevel
        self.loglevel_type = loglevel_type
        self.name = name
        self.filter_expression = filter_exp
        dbg._pdebug('server enable command {}'.format(self.__dict__))

    @classmethod
    def from_data(cls, header, data):
        try:
            loglevel, loglevel_type = cls._loglevel_struct.unpack_from(data)
            name_start = cls._loglevel_struct.size
            name_end = name_start + _LTTNG_SYMBOL_NAME_LEN
            data_name = data[name_start:name_end]
            name = data_name.rstrip(b'\0').decode()

            filter_exp_start = name_end + cls._filter_exp_len_struct.size
            filter_exp_len, = cls._filter_exp_len_struct.unpack_from(
                data[name_end:filter_exp_start])
            filter_exp_end = filter_exp_start + filter_exp_len

            filter_exp = data[filter_exp_start:filter_exp_end].rstrip(
                b'\0').decode()

            return cls(header, loglevel, loglevel_type, name, filter_exp)
        except (Exception) as e:
            dbg._pdebug('cannot decode enable command: {}'.format(e))
            return None


class _ServerCmdDisable(_ServerCmd):
    def __init__(self, header, name):
        super(self.__class__, self).__init__(header)
        self.name = name

    @classmethod
    def from_data(cls, header, data):
        try:
            name = data.rstrip(b'\0').decode()

            return cls(header, name)
        except (Exception) as e:
            dbg._pdebug('cannot decode disable command: {}'.format(e))
            return None


class _ServerCmdRegistrationDone(_ServerCmd):
    @classmethod
    def from_data(cls, header, data):
        return cls(header)


_SERVER_CMD_ID_TO_SERVER_CMD = {
    1: _ServerCmdList,
    2: _ServerCmdEnable,
    3: _ServerCmdDisable,
    4: _ServerCmdRegistrationDone,
}


def _server_cmd_from_data(header, data):
    if header.cmd_id not in _SERVER_CMD_ID_TO_SERVER_CMD:
        return None

    return _SERVER_CMD_ID_TO_SERVER_CMD[header.cmd_id].from_data(header, data)


_CLIENT_CMD_REPLY_STATUS_SUCCESS = 1
_CLIENT_CMD_REPLY_STATUS_INVALID_CMD = 2


class _ClientCmdReplyHeader(object):
    _payload_struct = struct.Struct('>I')

    def __init__(self, status_code=_CLIENT_CMD_REPLY_STATUS_SUCCESS):
        self.status_code = status_code

    def get_data(self):
        return self._payload_struct.pack(self.status_code)


class _ClientCmdReplyEnable(_ClientCmdReplyHeader):
    pass


class _ClientCmdReplyDisable(_ClientCmdReplyHeader):
    pass


class _ClientCmdReplyList(_ClientCmdReplyHeader):
    _nb_events_struct = struct.Struct('>I')
    _data_size_struct = struct.Struct('>I')

    def __init__(self, names, status_code=_CLIENT_CMD_REPLY_STATUS_SUCCESS):
        super(self.__class__, self).__init__(status_code)
        self.names = names

    def get_data(self):
        upper_data = super(self.__class__, self).get_data()
        nb_events_data = self._nb_events_struct.pack(len(self.names))
        names_data = bytes()

        for name in self.names:
            names_data += name.encode() + b'\0'

        data_size_data = self._data_size_struct.pack(len(names_data))

        return upper_data + data_size_data + nb_events_data + names_data


class _ClientRegisterCmd(object):
    _payload_struct = struct.Struct('>IIII')

    def __init__(self, domain, pid, major, minor):
        self.domain = domain
        self.pid = pid
        self.major = major
        self.minor = minor

    def get_data(self):
        return self._payload_struct.pack(self.domain, self.pid, self.major,
                                         self.minor)
