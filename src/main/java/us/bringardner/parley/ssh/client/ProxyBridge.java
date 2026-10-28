/**
 * <PRE>
 *
 * Copyright Tony Bringardner 2026 <A href="http://bringardner.com/tony">Tony Bringardner</A>
 *
 *
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *       <A href="http://www.apache.org/licenses/LICENSE-2.0">http://www.apache.org/licenses/LICENSE-2.0</A>
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 *  </PRE>
 *
 *
 *	@author Tony Bringardner
 *
 *
 * ~version~V000.00.01-V000.00.00-
 */
package us.bringardner.parley.ssh.client;

import java.io.Closeable;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import us.bringardner.parley.ssh.connection.ForwardingChannel;

/**
 * How {@link Ssh} reaches a server through something other than its own TCP connection
 * (ProxyJump, ProxyCommand): the SSH client connects to a port on 127.0.0.1 that accepts
 * one connection, then stops listening, and the bytes go through the jump host's channel or
 * the command's stdin and stdout. Whatever carries them, the server is still checked by its own
 * host key, under its own name.
 *
 * @author Tony Bringardner
 */
final class ProxyBridge implements Closeable {

	/** What the bytes go through, opened once the client has connected */
	interface Opener {
		void open(Socket socket) throws IOException;
	}

	private final ServerSocket listener;
	private final ExecutorService executor = Executors.newCachedThreadPool(r -> {
		Thread t = new Thread(r, "ssh-proxy");
		t.setDaemon(true);
		return t;
	});
	private volatile IOException failure;
	private volatile Process process;
	private volatile Socket socket;

	private ProxyBridge(Opener opener, int acceptTimeout) throws IOException {
		listener = new ServerSocket(0, 1, InetAddress.getLoopbackAddress());
		listener.setSoTimeout(acceptTimeout);
		executor.execute(() -> {
			try {
				Socket s;
				try {
					s = listener.accept();
				} finally {
					listener.close();
				}
				socket = s;
				try {
					opener.open(s);
				} catch (IOException e) {
					failure = e;
					s.close();
				}
			} catch (IOException e) {
				if( failure == null ) {
					failure = e;
				}
			}
		});
	}

	/** The port to connect to (on 127.0.0.1) */
	int getPort() {
		return listener.getLocalPort();
	}

	/** Why the other side couldn't be reached, or null */
	IOException getFailure() {
		return failure;
	}

	@Override
	public void close() {
		try {
			listener.close();
		} catch (IOException e) {
			// closing anyway
		}
		Socket s = socket;
		if( s != null ) {
			try {
				s.close();
			} catch (IOException e) {
				// closing anyway
			}
		}
		Process p = process;
		if( p != null ) {
			p.destroy();
		}
		executor.shutdownNow();
	}

	/** ProxyJump: through a direct-tcpip channel of the jump host's session */
	static ProxyBridge jump(ClientSession jumpHost, String host, int port) throws IOException {
		ProxyBridge[] self = new ProxyBridge[1];
		self[0] = new ProxyBridge(s -> {
			ForwardingChannel ch = jumpHost.openDirectTcpip(host, port);
			ch.bridge(s, self[0].executor);
		}, 60000);
		return self[0];
	}

	/** ProxyCommand: through a command's stdin and stdout (run by the shell); its stderr is ours */
	static ProxyBridge command(String command) throws IOException {
		ProxyBridge[] self = new ProxyBridge[1];
		self[0] = new ProxyBridge(s -> {
			ProcessBuilder pb;
			if( File.separatorChar == '\\' ) {
				pb = new ProcessBuilder("cmd.exe", "/c", command);
			} else {
				String shell = System.getenv("SHELL");
				pb = new ProcessBuilder(shell == null || shell.isEmpty() ? "/bin/sh" : shell, "-c", "exec "+command);
			}
			pb.redirectError(ProcessBuilder.Redirect.INHERIT);
			Process p = pb.start();
			self[0].process = p;
			InputStream fromSocket = s.getInputStream();
			OutputStream toSocket = s.getOutputStream();
			// The command's output ends: so does the connection. The client closes: the command's stdin ends.
			self[0].executor.execute(() -> copy(p.getInputStream(), toSocket, () -> closeQuietly(s)));
			self[0].executor.execute(() -> copy(fromSocket, p.getOutputStream(), () -> closeQuietly(p.getOutputStream())));
		}, 60000);
		return self[0];
	}

	private static void copy(InputStream in, OutputStream out, Runnable atEnd) {
		try {
			byte[] buf = new byte[32*1024];
			int n;
			while( (n = in.read(buf)) >= 0 ) {
				out.write(buf, 0, n);
				out.flush();
			}
		} catch (IOException e) {
			// one side closed
		} finally {
			atEnd.run();
		}
	}

	private static void closeQuietly(Closeable c) {
		try {
			c.close();
		} catch (IOException e) {
			// closed
		}
	}
}
