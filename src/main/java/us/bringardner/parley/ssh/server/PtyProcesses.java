/**
 * <PRE>
 * 
 * Copyright Tony Bringardner 1998, 2026 <A href="http://bringardner.com/tony">Tony Bringardner</A>
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
package us.bringardner.parley.ssh.server;

import java.io.File;
import java.io.IOException;
import java.util.List;
import java.util.Map;

import com.pty4j.PtyProcess;
import com.pty4j.PtyProcessBuilder;
import com.pty4j.WinSize;

/**
 * Processes on a pseudo terminal, through pty4j (an optional dependency). The only class
 * that uses pty4j, so the others load without it: check {@link #isAvailable()} first.
 *
 * @author Tony Bringardner
 */
final class PtyProcesses {

	private static final boolean AVAILABLE;

	static {
		boolean ok;
		try {
			Class.forName("com.pty4j.PtyProcessBuilder", false, PtyProcesses.class.getClassLoader());
			ok = true;
		} catch (ClassNotFoundException | LinkageError e) {
			ok = false;
		}
		AVAILABLE = ok;
	}

	private PtyProcesses() {
	}

	/**
	 * @return true if pty4j is on the class path
	 */
	static boolean isAvailable() {
		return AVAILABLE;
	}

	/**
	 * @return the process, with stdout and stderr both on the terminal (its input stream)
	 */
	static Process start(List<String> command, Map<String, String> env, File directory, int columns, int rows) throws IOException {
		int c = columns > 0 ? columns : 80;
		int r = rows > 0 ? rows : 24;
		PtyProcessBuilder b = new PtyProcessBuilder(sizedCommand(command, c, r))
				.setEnvironment(env)
				.setInitialColumns(c)
				.setInitialRows(r)
				.setRedirectErrorStream(true);
		if( directory != null ) {
			b.setDirectory(directory.getPath());
		}
		return b.start();
	}

	/**
	 * pty4j sets the terminal's initial size after the process has started (on Linux, at
	 * least with 0.14), so a command that asks for the size at once ("stty size", a
	 * full-screen program) can see 0 x 0. Where /bin/sh and stty exist, the command is
	 * started through "sh -c 'stty rows R cols C; exec \"$@\"'", which sets the size on
	 * the terminal itself before the command runs; exec replaces the shell, so the
	 * process is the command, as before.
	 */
	static String[] sizedCommand(List<String> command, int columns, int rows) {
		if( !STTY_WRAPPER || command.isEmpty() ) {
			return command.toArray(new String[0]);
		}
		List<String> ret = new java.util.ArrayList<String>();
		ret.add("/bin/sh");
		ret.add("-c");
		ret.add("stty rows "+rows+" cols "+columns+" 2>/dev/null; exec \"$@\"");
		ret.add("sh");
		ret.addAll(command);
		return ret.toArray(new String[0]);
	}

	//  Unix with /bin/sh and stty: the size is set before the command runs
	private static final boolean STTY_WRAPPER = !System.getProperty("os.name", "").toLowerCase().contains("win")
			&& new File("/bin/sh").canExecute() && hasStty();

	private static boolean hasStty() {
		for(String dir : new String[] {"/bin", "/usr/bin"}) {
			if( new File(dir, "stty").canExecute() ) {
				return true;
			}
		}
		return false;
	}

	static void resize(Process p, int columns, int rows) {
		if( p instanceof PtyProcess && columns > 0 && rows > 0 ) {
			((PtyProcess) p).setWinSize(new WinSize(columns, rows));
		}
	}
}
