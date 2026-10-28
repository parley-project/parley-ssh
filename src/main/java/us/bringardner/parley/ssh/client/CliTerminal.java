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

import java.io.Console;
import java.io.File;
import java.io.FileDescriptor;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintStream;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.concurrent.TimeUnit;

/**
 * What {@link SshMain} needs from the terminal it runs in: its streams, whether stdin is a
 * terminal, raw mode and the window size for a remote pseudo terminal, and prompts for
 * passwords and host keys (on the terminal even when stdin is redirected, as OpenSSH asks on
 * /dev/tty). {@link #system()} is the process's own; tests use another.
 *
 * @author Tony Bringardner
 */
abstract class CliTerminal {

	/** stdin: what is sent to the remote program */
	abstract InputStream in();

	/** stdout: what the remote program writes */
	abstract OutputStream out();

	/** stderr: the remote program's stderr, and this client's messages */
	abstract PrintStream err();

	/** stdin is a terminal */
	abstract boolean stdinIsTerminal();

	/**
	 * Raw mode: keys are passed on as typed (no echo, no line editing, Ctrl-C is a key), and
	 * output is written as it comes (no newline conversion).
	 *
	 * @return false if it can't be done
	 */
	abstract boolean enterRawMode();

	/** The terminal as it was before enterRawMode (safe to call more than once) */
	abstract void restore();

	/** @return {columns, rows}, or null if not known */
	abstract int[] size();

	/** Call listener when the window size changes (as often as it does) */
	abstract void onResize(Runnable listener);

	/**
	 * Ask the user.
	 *
	 * @param echo false for a secret (not shown as it is typed)
	 * @return the answer without its line end, or null if there is no one to ask (no terminal,
	 * end of input)
	 */
	abstract char[] prompt(String prompt, boolean echo);

	/** The process's terminal */
	static CliTerminal system() {
		return new SystemTerminal();
	}

	// ------------------------------------------------------------------ the process's

	static final class SystemTerminal extends CliTerminal {

		private static final boolean WINDOWS = File.separatorChar == '\\';
		private static final File DEV_TTY = new File("/dev/tty");

		private final InputStream in = new FileInputStream(FileDescriptor.in);
		private final OutputStream out = new FileOutputStream(FileDescriptor.out);
		private final PrintStream err = new PrintStream(new FileOutputStream(FileDescriptor.err), true);
		private Boolean stdinTerminal;
		/** stty -g before raw mode, null when not in raw mode */
		private String saved;
		/** echo is off on /dev/tty for a prompt */
		private volatile boolean ttyEchoOff;
		private boolean hookAdded;

		/** Put the terminal back when the JVM ends, e.g. at Ctrl-C during a prompt */
		private synchronized void addHook() {
			if( !hookAdded ) {
				hookAdded = true;
				Runtime.getRuntime().addShutdownHook(new Thread(() -> {
					restore();
					if( ttyEchoOff ) {
						stty(true, "echo");
					}
				}, "parley-ssh-restore-terminal"));
			}
		}

		@Override
		InputStream in() {
			return in;
		}

		@Override
		OutputStream out() {
			return out;
		}

		@Override
		PrintStream err() {
			return err;
		}

		@Override
		synchronized boolean stdinIsTerminal() {
			if( stdinTerminal == null ) {
				if( WINDOWS ) {
					stdinTerminal = console() != null;
				} else {
					// stty works only on a terminal: run it on our stdin
					stdinTerminal = stty(false, "-g") != null;
				}
			}
			return stdinTerminal;
		}

		@Override
		synchronized boolean enterRawMode() {
			if( WINDOWS || saved != null ) {
				return saved != null;
			}
			String s = stty(false, "-g");
			if( s == null ) {
				return false;
			}
			addHook();
			// As OpenSSH's raw mode (cfmakeraw): no echo, no line editing, no signals from keys,
			// no CR/NL conversions either way, no flow control keys
			if( stty(false, "raw", "-echo") == null ) {
				return false;
			}
			saved = s.trim();
			return true;
		}

		@Override
		synchronized void restore() {
			if( saved != null ) {
				stty(false, saved);
				saved = null;
			}
		}

		@Override
		int[] size() {
			if( WINDOWS ) {
				return null;
			}
			String s = stty(false, "size");
			if( s == null ) {
				s = stty(true, "size");
			}
			if( s != null ) {
				String[] w = s.trim().split("\\s+");
				if( w.length == 2 ) {
					try {
						int rows = Integer.parseInt(w[0]);
						int cols = Integer.parseInt(w[1]);
						if( rows > 0 && cols > 0 ) {
							return new int[] {cols, rows};
						}
					} catch (NumberFormatException e) {
						// not known
					}
				}
			}
			return null;
		}

		@Override
		void onResize(Runnable listener) {
			if( WINDOWS ) {
				return;
			}
			// sun.misc.Signal (jdk.unsupported), by reflection: it may not be there
			try {
				Class<?> signal = Class.forName("sun.misc.Signal");
				Class<?> handler = Class.forName("sun.misc.SignalHandler");
				Object winch = signal.getConstructor(String.class).newInstance("WINCH");
				InvocationHandler ih = (proxy, method, args) -> {
					if( method.getName().equals("handle") ) {
						new Thread(listener, "parley-ssh-resize").start();
					}
					return null;
				};
				Object h = Proxy.newProxyInstance(handler.getClassLoader(), new Class<?>[] {handler}, ih);
				Method handle = signal.getMethod("handle", signal, handler);
				handle.invoke(null, winch, h);
			} catch (ReflectiveOperationException | RuntimeException | LinkageError e) {
				// No resize events: the remote side keeps the first size
			}
		}

		@Override
		char[] prompt(String prompt, boolean echo) {
			Console c = console();
			if( c != null ) {
				if( echo ) {
					String s = c.readLine("%s", prompt);
					return s == null ? null : s.toCharArray();
				}
				return c.readPassword("%s", prompt);
			}
			if( WINDOWS || !DEV_TTY.canRead() || !DEV_TTY.canWrite() ) {
				return null;
			}
			// stdin or stdout is redirected: ask on the terminal itself
			try (FileInputStream tin = new FileInputStream(DEV_TTY); FileOutputStream tout = new FileOutputStream(DEV_TTY)) {
				tout.write(prompt.getBytes(Charset.defaultCharset()));
				tout.flush();
				if( !echo ) {
					addHook();
					ttyEchoOff = true;
					stty(true, "-echo");
				}
				byte[] line = new byte[256];
				int len = 0;
				try {
					int b;
					while( (b = tin.read()) >= 0 && b != '\n' ) {
						if( b == '\r' ) {
							continue;
						}
						if( len == line.length ) {
							byte[] bigger = Arrays.copyOf(line, len*2);
							Arrays.fill(line, (byte) 0);
							line = bigger;
						}
						line[len++] = (byte) b;
					}
					if( b < 0 && len == 0 ) {
						return null;
					}
					java.nio.CharBuffer chars = Charset.defaultCharset().decode(java.nio.ByteBuffer.wrap(line, 0, len));
					char[] ret = new char[chars.remaining()];
					chars.get(ret);
					if( chars.hasArray() ) {
						Arrays.fill(chars.array(), '\0');
					}
					return ret;
				} finally {
					Arrays.fill(line, (byte) 0);
					if( !echo ) {
						stty(true, "echo");
						ttyEchoOff = false;
						tout.write('\n');
					}
				}
			} catch (IOException e) {
				return null;
			}
		}

		/** System.console(), if it is a terminal (Java 22's may not be) */
		private static Console console() {
			Console c = System.console();
			if( c != null ) {
				try {
					Method m = Console.class.getMethod("isTerminal");
					if( !(Boolean) m.invoke(c) ) {
						return null;
					}
				} catch (ReflectiveOperationException e) {
					// before Java 22: a console is a terminal
				}
			}
			return c;
		}

		/**
		 * Run stty with stdin (devTty false) or /dev/tty (true) as its terminal.
		 *
		 * @return what it wrote, or null if it failed (not a terminal)
		 */
		private static String stty(boolean devTty, String... args) {
			String[] cmd = new String[args.length+1];
			cmd[0] = "stty";
			System.arraycopy(args, 0, cmd, 1, args.length);
			ProcessBuilder pb = new ProcessBuilder(cmd);
			pb.redirectInput(devTty ? ProcessBuilder.Redirect.from(DEV_TTY) : ProcessBuilder.Redirect.INHERIT);
			pb.redirectError(ProcessBuilder.Redirect.DISCARD);
			try {
				Process p = pb.start();
				byte[] o = p.getInputStream().readAllBytes();
				if( !p.waitFor(10, TimeUnit.SECONDS) ) {
					p.destroy();
					return null;
				}
				return p.exitValue() == 0 ? new String(o, StandardCharsets.US_ASCII) : null;
			} catch (IOException e) {
				return null;
			} catch (InterruptedException e) {
				Thread.currentThread().interrupt();
				return null;
			}
		}
	}
}
