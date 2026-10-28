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

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.PathMatcher;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.function.Consumer;

/**
 * Reads OpenSSH client config files (ssh_config(5)) into {@link SshOptions}: Host blocks
 * (patterns with * and ?, negated with !), Match blocks with "all", "host" and "originalhost"
 * (other criteria make the block not apply), and Include (with wildcards; relative names are in
 * ~/.ssh for the user's file, /etc/ssh for the system's).
 *
 * @author Tony Bringardner
 */
final class SshConfigFile {

	private static final int MAX_INCLUDE_DEPTH = 16;

	private final SshOptions options;
	private final Consumer<String> verbose;
	/** Lines of "Match final" blocks: used after every file was read (OpenSSH's final pass) */
	private final List<String[]> finalLines = new ArrayList<String[]>();
	/** while reading a block that applies only in the final pass */
	private boolean inFinal;

	/**
	 * @param verbose told about lines that are ignored (keywords this client doesn't use)
	 */
	SshConfigFile(SshOptions options, Consumer<String> verbose) {
		this.options = options;
		this.verbose = verbose;
	}

	/**
	 * Read a file (it need not exist).
	 *
	 * @param includeDir where relative Include names are
	 * @param user false for the system file: its problems are only reported
	 * @throws SshOptions.UsageException for a bad line in the user's file
	 */
	void read(File file, File includeDir, boolean user) throws IOException, SshOptions.UsageException {
		read(file, includeDir, user, true, 0);
	}

	private void read(File file, File includeDir, boolean user, boolean outerActive, int depth) throws IOException, SshOptions.UsageException {
		if( !file.isFile() ) {
			return;
		}
		if( depth > MAX_INCLUDE_DEPTH ) {
			throw new SshOptions.UsageException(file+": Include nested too deeply");
		}
		List<String> lines = Files.readAllLines(file.toPath(), StandardCharsets.UTF_8);
		// Lines before the first Host or Match apply to every host
		boolean active = outerActive;
		int n = 0;
		for (String line : lines) {
			n++;
			String t = line.trim();
			if( t.isEmpty() || t.startsWith("#") ) {
				continue;
			}
			List<String> words = SshOptions.tokenize(t);
			if( words.isEmpty() ) {
				continue;
			}
			String key = words.get(0).toLowerCase(Locale.ROOT);
			List<String> args = words.subList(1, words.size());
			try {
				switch (key) {
				case "host":
					inFinal = false;
					active = outerActive && hostMatches(args);
					break;
				case "match":
					inFinal = false;
					active = outerActive && matchApplies(file, n, args);
					break;
				case "include":
					if( active ) {
						for (String pattern : args) {
							for (File f : includes(pattern, includeDir)) {
								read(f, includeDir, user, true, depth+1);
							}
						}
					}
					break;
				default:
					if( active && inFinal ) {
						finalLines.add(new String[] {file+" line "+n, t, String.valueOf(user)});
					} else if( active && !options.set(key, key.equals("proxycommand") ? Arrays.asList(SshOptions.rawValue(t)) : args) ) {
						if( !SshOptions.isIgnored(key) ) {
							verbose.accept(file+" line "+n+": "+words.get(0)+" is not supported, ignored");
						}
					}
				}
			} catch (SshOptions.UsageException e) {
				if( user ) {
					throw new SshOptions.UsageException(file+" line "+n+": "+e.getMessage());
				}
				verbose.accept(file+" line "+n+": "+e.getMessage());
			}
		}
	}

	/**
	 * After the last file: the settings of "Match final" blocks, for what is still unset
	 * (OpenSSH reads the files again for them; values found the first time win).
	 */
	void finish() throws SshOptions.UsageException {
		for (String[] l : finalLines) {
			List<String> words = SshOptions.tokenize(l[1]);
			String key = words.get(0).toLowerCase(Locale.ROOT);
			try {
				List<String> args = key.equals("proxycommand") ? Arrays.asList(SshOptions.rawValue(l[1])) : words.subList(1, words.size());
				if( !options.set(key, args) && !SshOptions.isIgnored(key) ) {
					verbose.accept(l[0]+": "+words.get(0)+" is not supported, ignored");
				}
			} catch (SshOptions.UsageException e) {
				if( Boolean.parseBoolean(l[2]) ) {
					throw new SshOptions.UsageException(l[0]+": "+e.getMessage());
				}
				verbose.accept(l[0]+": "+e.getMessage());
			}
		}
		finalLines.clear();
	}

	private boolean hostMatches(List<String> patterns) {
		return matches(options.host, patterns);
	}

	/**
	 * @return true if one of the patterns matches and no negated one does
	 */
	static boolean matches(String name, List<String> patterns) {
		boolean ret = false;
		for (String p : patterns) {
			for (String one : p.split(",")) {
				if( one.startsWith("!") ) {
					if( glob(one.substring(1), name) ) {
						return false;
					}
				} else if( glob(one, name) ) {
					ret = true;
				}
			}
		}
		return ret;
	}

	/** * any characters, ? one; not case sensitive (host names aren't) */
	static boolean glob(String pattern, String name) {
		return glob(pattern.toLowerCase(Locale.ROOT), 0, name.toLowerCase(Locale.ROOT), 0);
	}

	private static boolean glob(String p, int pi, String s, int si) {
		while( pi < p.length() ) {
			char c = p.charAt(pi);
			if( c == '*' ) {
				for (int k = si; k <= s.length(); k++) {
					if( glob(p, pi+1, s, k) ) {
						return true;
					}
				}
				return false;
			}
			if( si >= s.length() || (c != '?' && c != s.charAt(si)) ) {
				return false;
			}
			pi++;
			si++;
		}
		return si == s.length();
	}

	private boolean matchApplies(File file, int line, List<String> args) {
		boolean ret = true;
		for (int i = 0; i < args.size(); i++) {
			String c = args.get(i).toLowerCase(Locale.ROOT);
			boolean negate = c.startsWith("!");
			if( negate ) {
				c = c.substring(1);
			}
			boolean ok;
			switch (c) {
			case "all":
				ok = true;
				break;
			case "final":
				// Applies in the final pass: see finish()
				ok = true;
				if( !negate ) {
					inFinal = true;
				}
				break;
			case "host":
			case "originalhost":
				if( i+1 >= args.size() ) {
					verbose.accept(file+" line "+line+": Match "+c+" needs patterns");
					return false;
				}
				String name = c.equals("host") && options.hostName != null
						? options.hostName.replace("%h", options.host) : options.host;
				ok = matches(name, Arrays.asList(args.get(++i)));
				break;
			default:
				verbose.accept(file+" line "+line+": Match "+c+" is not supported; the block is skipped");
				return false;
			}
			ret &= negate ? !ok : ok;
		}
		return ret;
	}

	private List<File> includes(String pattern, File includeDir) {
		String path = options.expand(pattern);
		File f = new File(path);
		if( !f.isAbsolute() ) {
			f = new File(includeDir, path);
		}
		List<File> ret = new ArrayList<File>();
		expandGlob(f.getAbsoluteFile(), ret);
		ret.sort(null);
		return ret;
	}

	private static boolean hasWildcard(String s) {
		return s.indexOf('*') >= 0 || s.indexOf('?') >= 0 || s.indexOf('[') >= 0;
	}

	/** The files a path with wildcards in any of its names matches */
	private static void expandGlob(File f, List<File> out) {
		File parent = f.getParentFile();
		if( !hasWildcard(f.getPath()) ) {
			out.add(f);
			return;
		}
		List<File> dirs = new ArrayList<File>();
		if( parent == null ) {
			return;
		}
		expandGlob(parent, dirs);
		String name = f.getName();
		for (File d : dirs) {
			if( !hasWildcard(name) ) {
				out.add(new File(d, name));
				continue;
			}
			File[] list = d.listFiles();
			if( list == null ) {
				continue;
			}
			PathMatcher m = FileSystems.getDefault().getPathMatcher("glob:"+name);
			for (File c : list) {
				if( m.matches(c.toPath().getFileName()) ) {
					out.add(c);
				}
			}
		}
	}
}
