/*
 * Copyright (C) 2013 - David Goulet <dgoulet@efficios.com>
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License, version 2.1 only,
 * as published by the Free Software Foundation.
 *
 * This library is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License
 * for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

package org.lttng.ust.agent;

import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.lang.management.ManagementFactory;
import java.net.Socket;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.concurrent.Semaphore;

class LTTngTCPSessiondClient implements Runnable {

	/* Command header from the session deamon. */
	private LTTngSessiondCmd2_6.sessiond_hdr headerCmd =
		new LTTngSessiondCmd2_6.sessiond_hdr();

	private Socket sessiondSock;
	private volatile boolean quit = false;

	private DataInputStream inFromSessiond;
	private DataOutputStream outToSessiond;

	private LogFramework log;

	private Semaphore registerSem;

	private static final String sessiondHost = "127.0.0.1";
	private static final String rootPortFile = "/var/run/lttng/agent.port";
	private static final String userPortFile = "/.lttng/agent.port";

	private static Integer protocolMajorVersion = 1;
	private static Integer protocolMinorVersion = 0;

	private LTTngAgent.Domain agentDomain;

	/* Indicate if we've already release the semaphore. */
	private boolean sem_posted = false;

	public LTTngTCPSessiondClient(LTTngAgent.Domain domain, LogFramework log, Semaphore sem) {
		this.agentDomain = domain;
		this.log = log;
		this.registerSem = sem;
	}

	/*
	 * Try to release the registerSem if it's not already done.
	 */
	private void tryReleaseSem()
	{
		/* Release semaphore so we unblock the agent. */
		if (!this.sem_posted) {
			this.registerSem.release();
			this.sem_posted = true;
		}
	}

	@Override
	public void run() {
		for (;;) {
			if (this.quit) {
				break;
			}

			/* Cleanup Agent state before trying to connect or reconnect. */
			this.log.reset();

			try {

				/*
				 * Connect to the session daemon before anything else.
				 */
				connectToSessiond();

				/*
				 * Register to the session daemon as the Java component of the
				 * UST application.
				 */
				registerToSessiond();

				/*
				 * Block on socket receive and wait for command from the
				 * session daemon. This will return if and only if there is a
				 * fatal error or the socket closes.
				 */
				handleSessiondCmd();
			} catch (UnknownHostException uhe) {
				tryReleaseSem();
				System.out.println(uhe);
			} catch (IOException ioe) {
				tryReleaseSem();
				try {
					Thread.sleep(3000);
				} catch (InterruptedException e) {
					e.printStackTrace();
				}
			} catch (Exception e) {
				tryReleaseSem();
				e.printStackTrace();
			}
		}
	}

	public void destroy() {
		this.quit = true;

		try {
			if (this.sessiondSock != null) {
				this.sessiondSock.close();
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	/*
	 * Receive header data from the session daemon using the LTTng command
	 * static buffer of the right size.
	 */
	private void recvHeader() throws Exception {
		int read_len;
		byte data[] = new byte[LTTngSessiondCmd2_6.sessiond_hdr.SIZE];

		read_len = this.inFromSessiond.read(data, 0, data.length);
		if (read_len != data.length) {
			throw new IOException();
		}
		this.headerCmd.populate(data);
	}

	/*
	 * Receive payload from the session daemon. This MUST be done after a
	 * recvHeader() so the header value of a command are known.
	 *
	 * The caller SHOULD use isPayload() before which returns true if a payload
	 * is expected after the header.
	 */
	private byte[] recvPayload() throws Exception {
		byte payload[] = new byte[(int) this.headerCmd.data_size];

		/* Failsafe check so we don't waste our time reading 0 bytes. */
		if (payload.length == 0) {
			return null;
		}

		this.inFromSessiond.read(payload, 0, payload.length);
		return payload;
	}

	/*
	 * Handle session command from the session daemon.
	 */
	private void handleSessiondCmd() throws Exception {
		byte data[] = null;

		while (true) {
			/* Get header from session daemon. */
			recvHeader();

			if (headerCmd.data_size > 0) {
				data = recvPayload();
			}

			switch (headerCmd.cmd) {
				case CMD_REG_DONE:
				{
					/*
					 * Check command version:
					 *
					 *   * 0:  Connected to a non-fixed session daemon,
					 *         which could send multiple disable
					 *         event commands: do not decrement
					 *         reference count on disable event command
					 *         (original behaviour).
					 *   * >0: Connected to a fixed session daemon:
					 *         do decrement reference count on disable
					 *         event command.
					 */
					if (headerCmd.cmd_version > 0) {
						this.log.setEnableRefCountDecrement(true);
					}

					/*
					 * Release semaphore so meaning registration is done and we
					 * can proceed to continue tracing.
					 */
					tryReleaseSem();
					/*
					 * We don't send any reply to the registration done command.
					 * This just marks the end of the initial session setup.
					 */
					continue;
				}
				case CMD_LIST:
				{
					LTTngSessiondCmd2_6.sessiond_list_logger listLoggerCmd =
						new LTTngSessiondCmd2_6.sessiond_list_logger();
					listLoggerCmd.execute(this.log);
					data = listLoggerCmd.getBytes();
					break;
				}
				case CMD_ENABLE:
				{
					LTTngSessiondCmd2_6.sessiond_enable_handler enableCmd =
						new LTTngSessiondCmd2_6.sessiond_enable_handler();
					if (data == null) {
						enableCmd.code = LTTngSessiondCmd2_6.lttng_agent_ret_code.CODE_INVALID_CMD;
						break;
					}
					enableCmd.populate(data);
					enableCmd.execute(this.log);
					data = enableCmd.getBytes();
					break;
				}
				case CMD_DISABLE:
				{
					LTTngSessiondCmd2_6.sessiond_disable_handler disableCmd =
						new LTTngSessiondCmd2_6.sessiond_disable_handler();
					if (data == null) {
						disableCmd.code = LTTngSessiondCmd2_6.lttng_agent_ret_code.CODE_INVALID_CMD;
						break;
					}
					disableCmd.populate(data);
					disableCmd.execute(this.log);
					data = disableCmd.getBytes();
					break;
				}
				default:
				{
					data = new byte[4];
					ByteBuffer buf = ByteBuffer.wrap(data);
					buf.order(ByteOrder.BIG_ENDIAN);
					break;
				}
			}

			/* Send payload to session daemon. */
			this.outToSessiond.write(data, 0, data.length);
			this.outToSessiond.flush();
		}
	}

	private static String getHomePath() {
		/*
		 * The environment variable LTTNG_HOME overrides HOME if
		 * defined.
		 */
		String homePath = System.getenv("LTTNG_HOME");

		if (homePath == null) {
		homePath = System.getProperty("user.home");
		}
		return homePath;
	}

	/**
	 * Read port number from file created by the session daemon.
	 *
	 * @return port value if found else 0.
	 */
	private static int getPortFromFile(String path) throws IOException {
		int port;
		BufferedReader br;

		try {
			br = new BufferedReader(new FileReader(path));
			String line = br.readLine();
			port = Integer.parseInt(line, 10);
			if (port < 0 || port > 65535) {
				/* Invalid value. Ignore. */
				port = 0;
			}
			br.close();
		} catch (FileNotFoundException e) {
			/* No port available. */
			port = 0;
		}

		return port;
	}

	private void connectToSessiond() throws Exception {
		int port;

		if (this.log.isRoot()) {
			port = getPortFromFile(rootPortFile);
			if (port == 0) {
				/* No session daemon available. Stop and retry later. */
				throw new IOException();
			}
		} else {
			port = getPortFromFile(getHomePath() + userPortFile);
			if (port == 0) {
				/* No session daemon available. Stop and retry later. */
				throw new IOException();
			}
		}

		this.sessiondSock = new Socket(sessiondHost, port);
		this.inFromSessiond = new DataInputStream(
				sessiondSock.getInputStream());
		this.outToSessiond = new DataOutputStream(
				sessiondSock.getOutputStream());
	}

	private void registerToSessiond() throws Exception {
		byte data[] = new byte[16];
		ByteBuffer buf = ByteBuffer.wrap(data);
		String pid = ManagementFactory.getRuntimeMXBean().getName().split("@")[0];

		buf.putInt(this.agentDomain.value());
		buf.putInt(Integer.parseInt(pid));
		buf.putInt(protocolMajorVersion);
		buf.putInt(protocolMinorVersion);
		this.outToSessiond.write(data, 0, data.length);
		this.outToSessiond.flush();
	}
}
