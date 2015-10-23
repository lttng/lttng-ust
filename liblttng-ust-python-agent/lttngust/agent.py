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
from __future__ import print_function
from __future__ import division
import lttngust.debug as dbg
import lttngust.loghandler
import lttngust.cmd
from io import open
import threading
import logging
import socket
import time
import sys
import os


try:
    # Python 2
    import Queue as queue
except ImportError:
    # Python 3
    import queue


_PROTO_DOMAIN = 5
_PROTO_MAJOR = 2
_PROTO_MINOR = 0


def _get_env_value_ms(key, default_s):
    try:
        val = int(os.getenv(key, default_s * 1000)) / 1000
    except:
        val = -1

    if val < 0:
        fmt = 'invalid ${} value; {} seconds will be used'
        dbg._pwarning(fmt.format(key, default_s))
        val = default_s

    return val


_REG_TIMEOUT = _get_env_value_ms('LTTNG_UST_PYTHON_REGISTER_TIMEOUT', 5)
_RETRY_REG_DELAY = _get_env_value_ms('LTTNG_UST_PYTHON_REGISTER_RETRY_DELAY', 3)


class _TcpClient(object):
    def __init__(self, name, host, port, reg_queue):
        super(self.__class__, self).__init__()
        self._name = name
        self._host = host
        self._port = port

        try:
            self._log_handler = lttngust.loghandler._Handler()
        except (OSError) as e:
            dbg._pwarning('cannot load library: {}'.format(e))
            raise e

        self._root_logger = logging.getLogger()
        self._root_logger.setLevel(logging.NOTSET)
        self._ref_count = 0
        self._sessiond_sock = None
        self._reg_queue = reg_queue
        self._server_cmd_handlers = {
            lttngust.cmd._ServerCmdRegistrationDone: self._handle_server_cmd_reg_done,
            lttngust.cmd._ServerCmdEnable: self._handle_server_cmd_enable,
            lttngust.cmd._ServerCmdDisable: self._handle_server_cmd_disable,
            lttngust.cmd._ServerCmdList: self._handle_server_cmd_list,
        }

    def _debug(self, msg):
        return 'client "{}": {}'.format(self._name, msg)

    def run(self):
        while True:
            try:
                # connect to the session daemon
                dbg._pdebug(self._debug('connecting to session daemon'))
                self._connect_to_sessiond()

                # register to the session daemon after a successful connection
                dbg._pdebug(self._debug('registering to session daemon'))
                self._register()

                # wait for commands from the session daemon
                self._wait_server_cmd()
            except (Exception) as e:
                # Whatever happens here, we have to close the socket and
                # retry to connect to the session daemon since either
                # the socket was closed, a network timeout occured, or
                # invalid data was received.
                dbg._pdebug(self._debug('got exception: {}'.format(e)))
                self._cleanup_socket()
                dbg._pdebug(self._debug('sleeping for {} s'.format(_RETRY_REG_DELAY)))
                time.sleep(_RETRY_REG_DELAY)

    def _recv_server_cmd_header(self):
        data = self._sessiond_sock.recv(lttngust.cmd._SERVER_CMD_HEADER_SIZE)

        if not data:
            dbg._pdebug(self._debug('received empty server command header'))
            return None

        assert(len(data) == lttngust.cmd._SERVER_CMD_HEADER_SIZE)
        dbg._pdebug(self._debug('received server command header ({} bytes)'.format(len(data))))

        return lttngust.cmd._server_cmd_header_from_data(data)

    def _recv_server_cmd(self):
        server_cmd_header = self._recv_server_cmd_header()

        if server_cmd_header is None:
            return None

        dbg._pdebug(self._debug('server command header: data size: {} bytes'.format(server_cmd_header.data_size)))
        dbg._pdebug(self._debug('server command header: command ID: {}'.format(server_cmd_header.cmd_id)))
        dbg._pdebug(self._debug('server command header: command version: {}'.format(server_cmd_header.cmd_version)))
        data = bytes()

        if server_cmd_header.data_size > 0:
            data = self._sessiond_sock.recv(server_cmd_header.data_size)
            assert(len(data) == server_cmd_header.data_size)

        return lttngust.cmd._server_cmd_from_data(server_cmd_header, data)

    def _send_cmd_reply(self, cmd_reply):
        data = cmd_reply.get_data()
        dbg._pdebug(self._debug('sending command reply ({} bytes)'.format(len(data))))
        self._sessiond_sock.sendall(data)

    def _handle_server_cmd_reg_done(self, server_cmd):
        dbg._pdebug(self._debug('got "registration done" server command'))

        if self._reg_queue is not None:
            dbg._pdebug(self._debug('notifying _init_threads()'))

            try:
                self._reg_queue.put(True)
            except (Exception) as e:
                # read side could be closed by now; ignore it
                pass

            self._reg_queue = None

    def _handle_server_cmd_enable(self, server_cmd):
        dbg._pdebug(self._debug('got "enable" server command'))
        self._ref_count += 1

        if self._ref_count == 1:
            dbg._pdebug(self._debug('adding our handler to the root logger'))
            self._root_logger.addHandler(self._log_handler)

        dbg._pdebug(self._debug('ref count is {}'.format(self._ref_count)))

        return lttngust.cmd._ClientCmdReplyEnable()

    def _handle_server_cmd_disable(self, server_cmd):
        dbg._pdebug(self._debug('got "disable" server command'))
        self._ref_count -= 1

        if self._ref_count < 0:
            # disable command could be sent again when a session is destroyed
            self._ref_count = 0

        if self._ref_count == 0:
            dbg._pdebug(self._debug('removing our handler from the root logger'))
            self._root_logger.removeHandler(self._log_handler)

        dbg._pdebug(self._debug('ref count is {}'.format(self._ref_count)))

        return lttngust.cmd._ClientCmdReplyDisable()

    def _handle_server_cmd_list(self, server_cmd):
        dbg._pdebug(self._debug('got "list" server command'))
        names = logging.Logger.manager.loggerDict.keys()
        dbg._pdebug(self._debug('found {} loggers'.format(len(names))))
        cmd_reply = lttngust.cmd._ClientCmdReplyList(names=names)

        return cmd_reply

    def _handle_server_cmd(self, server_cmd):
        cmd_reply = None

        if server_cmd is None:
            dbg._pdebug(self._debug('bad server command'))
            status = lttngust.cmd._CLIENT_CMD_REPLY_STATUS_INVALID_CMD
            cmd_reply = lttngust.cmd._ClientCmdReply(status)
        elif type(server_cmd) in self._server_cmd_handlers:
            cmd_reply = self._server_cmd_handlers[type(server_cmd)](server_cmd)
        else:
            dbg._pdebug(self._debug('unknown server command'))
            status = lttngust.cmd._CLIENT_CMD_REPLY_STATUS_INVALID_CMD
            cmd_reply = lttngust.cmd._ClientCmdReply(status)

        if cmd_reply is not None:
            self._send_cmd_reply(cmd_reply)

    def _wait_server_cmd(self):
        while True:
            try:
                server_cmd = self._recv_server_cmd()
            except socket.timeout:
                # simply retry here; the protocol has no KA and we could
                # wait for hours
                continue

            self._handle_server_cmd(server_cmd)

    def _cleanup_socket(self):
        try:
            self._sessiond_sock.shutdown(socket.SHUT_RDWR)
            self._sessiond_sock.close()
        except:
            pass

        self._sessiond_sock = None

    def _connect_to_sessiond(self):
        # create session daemon TCP socket
        if self._sessiond_sock is None:
            self._sessiond_sock = socket.socket(socket.AF_INET,
                                                socket.SOCK_STREAM)

        # Use str(self._host) here. Since this host could be a string
        # literal, and since we're importing __future__.unicode_literals,
        # we want to make sure the host is a native string in Python 2.
        # This avoids an indirect module import (unicode module to
        # decode the unicode string, eventually imported by the
        # socket module if needed), which is not allowed in a thread
        # directly created by a module in Python 2 (our case).
        #
        # tl;dr: Do NOT remove str() here, or this call in Python 2
        # _will_ block on an interpreter's mutex until the waiting
        # register queue timeouts.
        self._sessiond_sock.connect((str(self._host), self._port))

    def _register(self):
        cmd = lttngust.cmd._ClientRegisterCmd(_PROTO_DOMAIN, os.getpid(),
                                              _PROTO_MAJOR, _PROTO_MINOR)
        data = cmd.get_data()
        self._sessiond_sock.sendall(data)


def _get_port_from_file(path):
    port = None
    dbg._pdebug('reading port from file "{}"'.format(path))

    try:
        f = open(path)
        r_port = int(f.readline())
        f.close()

        if r_port > 0 or r_port <= 65535:
            port = r_port
    except:
        pass

    return port


def _get_user_home_path():
    # $LTTNG_HOME overrides $HOME if it exists
    return os.getenv('LTTNG_HOME', os.path.expanduser('~'))


_initialized = False
_SESSIOND_HOST = '127.0.0.1'


def _client_thread_target(name, port, reg_queue):
    dbg._pdebug('creating client "{}" using TCP port {}'.format(name, port))
    client = _TcpClient(name, _SESSIOND_HOST, port, reg_queue)
    dbg._pdebug('starting client "{}"'.format(name))
    client.run()


def _init_threads():
    global _initialized

    dbg._pdebug('entering')

    if _initialized:
        dbg._pdebug('agent is already initialized')
        return

    # This makes sure that the appropriate modules for encoding and
    # decoding strings/bytes are imported now, since no import should
    # happen within a thread at import time (our case).
    'lttng'.encode().decode()

    _initialized = True
    sys_port = _get_port_from_file('/var/run/lttng/agent.port')
    user_port_file = os.path.join(_get_user_home_path(), '.lttng', 'agent.port')
    user_port = _get_port_from_file(user_port_file)
    reg_queue = queue.Queue()
    reg_expecting = 0

    dbg._pdebug('system session daemon port: {}'.format(sys_port))
    dbg._pdebug('user session daemon port: {}'.format(user_port))

    if sys_port == user_port and sys_port is not None:
        # The two session daemon ports are the same. This is not normal.
        # Connect to only one.
        dbg._pdebug('both user and system session daemon have the same port')
        sys_port = None

    try:
        if sys_port is not None:
            dbg._pdebug('creating system client thread')
            t = threading.Thread(target=_client_thread_target,
                                 args=('system', sys_port, reg_queue))
            t.name = 'system'
            t.daemon = True
            t.start()
            dbg._pdebug('created and started system client thread')
            reg_expecting += 1

        if user_port is not None:
            dbg._pdebug('creating user client thread')
            t = threading.Thread(target=_client_thread_target,
                                 args=('user', user_port, reg_queue))
            t.name = 'user'
            t.daemon = True
            t.start()
            dbg._pdebug('created and started user client thread')
            reg_expecting += 1
    except:
        # cannot create threads for some reason; stop this initialization
        dbg._pwarning('cannot create client threads')
        return

    if reg_expecting == 0:
        # early exit: looks like there's not even one valid port
        dbg._pwarning('no valid LTTng session daemon port found (is the session daemon started?)')
        return

    cur_timeout = _REG_TIMEOUT

    # We block here to make sure the agent is properly registered to
    # the session daemon. If we timeout, the client threads will still
    # continue to try to connect and register to the session daemon,
    # but there is no guarantee that all following logging statements
    # will make it to LTTng-UST.
    #
    # When a client thread receives a "registration done" confirmation
    # from the session daemon it's connected to, it puts True in
    # reg_queue.
    while True:
        try:
            dbg._pdebug('waiting for registration done (expecting {}, timeout is {} s)'.format(reg_expecting,
                                                                                               cur_timeout))
            t1 = time.clock()
            reg_queue.get(timeout=cur_timeout)
            t2 = time.clock()
            reg_expecting -= 1
            dbg._pdebug('unblocked')

            if reg_expecting == 0:
                # done!
                dbg._pdebug('successfully registered to session daemon(s)')
                break

            cur_timeout -= (t2 - t1)

            if cur_timeout <= 0:
                # timeout
                dbg._pdebug('ran out of time')
                break
        except queue.Empty:
            dbg._pdebug('ran out of time')
            break

    dbg._pdebug('leaving')


_init_threads()
