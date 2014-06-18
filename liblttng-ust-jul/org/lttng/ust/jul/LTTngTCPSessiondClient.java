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

package org.lttng.ust.jul;

import java.util.concurrent.Semaphore;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.lang.Integer;
import java.io.IOException;
import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.DataInputStream;
import java.io.FileReader;
import java.io.FileNotFoundException;
import java.net.*;
import java.lang.management.ManagementFactory;
import java.util.logging.Logger;

class USTRegisterMsg {
	public static int pid;
}

public class LTTngTCPSessiondClient {
	/* Command header from the session deamon. */
	private LTTngSessiondCmd2_4.sessiond_hdr headerCmd =
		new LTTngSessiondCmd2_4.sessiond_hdr();

	private final String sessiondHost;
	private Socket sessiondSock;
	private boolean quit = false;

	private DataInputStream inFromSessiond;
	private DataOutputStream outToSessiond;

	private LTTngLogHandler handler;

	private Semaphore registerSem;

	private static final String rootPortFile = "/var/run/lttng/jul.port";
	private static final String userPortFile = "/.lttng/jul.port";

	/* Indicate if we've already release the semaphore. */
	private boolean sem_posted = false;

	public LTTngTCPSessiondClient(String host, Semaphore sem) {
		this.sessiondHost = host;
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

	/*
	 * Cleanup Agent state.
	 */
	private void cleanupState() {
		if (this.handler != null) {
			this.handler.clear();
		}
	}

	public void init(LTTngLogHandler handler) throws InterruptedException {
		this.handler = handler;

		for (;;) {
			if (this.quit) {
				break;
			}

			/* Cleanup Agent state before trying to connect or reconnect. */
			cleanupState();

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
				Thread.sleep(3000);
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
		byte data[] = new byte[this.headerCmd.SIZE];

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
		int ret_code;
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
					LTTngSessiondCmd2_4.sessiond_list_logger listLoggerCmd =
						new LTTngSessiondCmd2_4.sessiond_list_logger();
					listLoggerCmd.execute(this.handler);
					data = listLoggerCmd.getBytes();
					break;
				}
				case CMD_ENABLE:
				{
					LTTngEvent event;
					LTTngSessiondCmd2_4.sessiond_enable_handler enableCmd =
						new LTTngSessiondCmd2_4.sessiond_enable_handler();
					if (data == null) {
						enableCmd.code = LTTngSessiondCmd2_4.lttng_jul_ret_code.CODE_INVALID_CMD;
						break;
					}
					enableCmd.populate(data);
					enableCmd.execute(this.handler);
					data = enableCmd.getBytes();
					break;
				}
				case CMD_DISABLE:
				{
					LTTngSessiondCmd2_4.sessiond_disable_handler disableCmd =
						new LTTngSessiondCmd2_4.sessiond_disable_handler();
					if (data == null) {
						disableCmd.code = LTTngSessiondCmd2_4.lttng_jul_ret_code.CODE_INVALID_CMD;
						break;
					}
					disableCmd.populate(data);
					disableCmd.execute(this.handler);
					data = disableCmd.getBytes();
					break;
				}
				default:
				{
					data = new byte[4];
					ByteBuffer buf = ByteBuffer.wrap(data);
					buf.order(ByteOrder.BIG_ENDIAN);
					LTTngSessiondCmd2_4.lttng_jul_ret_code code =
						LTTngSessiondCmd2_4.lttng_jul_ret_code.CODE_INVALID_CMD;
					buf.putInt(code.getCode());
					break;
				}
			}

			/* Send payload to session daemon. */
			this.outToSessiond.write(data, 0, data.length);
			this.outToSessiond.flush();
		}
	}

	private String getHomePath() {
		return System.getProperty("user.home");
	}

	/**
	 * Read port number from file created by the session daemon.
	 *
	 * @return port value if found else 0.
	 */
	private int getPortFromFile(String path) throws IOException {
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

		if (this.handler.is_root == 1) {
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

		this.sessiondSock = new Socket(this.sessiondHost, port);
		this.inFromSessiond = new DataInputStream(
				sessiondSock.getInputStream());
		this.outToSessiond = new DataOutputStream(
				sessiondSock.getOutputStream());
	}

	private void registerToSessiond() throws Exception {
		byte data[] = new byte[4];
		ByteBuffer buf = ByteBuffer.wrap(data);
		String pid = ManagementFactory.getRuntimeMXBean().getName().split("@")[0];

		buf.putInt(Integer.parseInt(pid));
		this.outToSessiond.write(data, 0, data.length);
		this.outToSessiond.flush();
	}
}
