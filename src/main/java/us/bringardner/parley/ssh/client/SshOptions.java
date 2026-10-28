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
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * The settings of one {@link Ssh} run: its command line (OpenSSH's options), then the
 * ssh_config files. As in OpenSSH the first value obtained for a setting is used, so the
 * command line wins over the files and the first matching Host block wins over later ones;
 * settings that are lists (IdentityFile, LocalForward, RemoteForward, SendEnv...) collect every
 * value.
 *
 * @author Tony Bringardner
 */
final class SshOptions {

	/** A bad command line or setting; the message is shown with "ssh: " in front */
	static final class UsageException extends Exception {
		private static final long serialVersionUID = 1L;
		UsageException(String message) {
			super(message);
		}
	}

	/** One -L or -R: listen on bindHost:bindPort and connect to host:port */
	static final class Forward {
		final String bindHost;
		final int bindPort;
		final String host;
		final int port;

		Forward(String bindHost, int bindPort, String host, int port) {
			this.bindHost = bindHost;
			this.bindPort = bindPort;
			this.host = host;
			this.port = port;
		}

		@Override
		public String toString() {
			return (bindHost == null ? "" : bindHost+":")+bindPort+":"+host+":"+port;
		}
	}

	/** OpenSSH's single-letter options that take an argument */
	private static final String WITH_ARGUMENT = "BbcDEeFIiJLlmOopQRSWw";
	/** The single-letter options without an argument */
	private static final String FLAGS = "46AaCfGgKkMNnqsTtVvXxYy";

	/** The default identity files, in OpenSSH's order */
	static final List<String> DEFAULT_IDENTITIES = Arrays.asList(
			"~/.ssh/id_rsa", "~/.ssh/id_ecdsa", "~/.ssh/id_ecdsa_sk", "~/.ssh/id_ed25519", "~/.ssh/id_ed25519_sk");

	// ------------------------------------------------------------------ from the command line only

	/** The host as typed (user@ and :port removed), what Host lines match */
	String host;
	/** The command to run: the rest of the command line, joined by spaces; null for a shell */
	String command;
	/** -s: the command is a subsystem */
	boolean subsystem;
	/** -N: no command, no shell (port forwarding only) */
	boolean noCommand;
	/** -n: nothing is read from stdin */
	boolean stdinNull;
	/** -V */
	boolean showVersion;
	/** -v (each one more) */
	int verbose;
	/** -F: the config file to read instead of the usual ones, "none" for none */
	String configFile;
	/** -t given twice: a terminal even if stdin isn't one */
	int ttyFlags;
	/** -h or --help */
	boolean help;

	// ------------------------------------------------------------------ settings (ssh_config keywords)

	String hostName;
	String user;
	Integer port;
	final List<String> identityFiles = new ArrayList<String>();
	final List<String> certificateFiles = new ArrayList<String>();
	Boolean identitiesOnly;
	String identityAgent;
	String strictHostKeyChecking;
	List<String> userKnownHostsFiles;
	List<String> globalKnownHostsFiles;
	Boolean hashKnownHosts;
	String forwardAgent;
	final List<Forward> localForwards = new ArrayList<Forward>();
	final List<Forward> remoteForwards = new ArrayList<Forward>();
	Boolean exitOnForwardFailure;
	Integer serverAliveInterval;
	Integer serverAliveCountMax;
	Integer connectTimeout;
	Boolean compression;
	/** yes, no, force, auto */
	String requestTty;
	Boolean batchMode;
	Boolean passwordAuthentication;
	Boolean pubkeyAuthentication;
	Boolean kbdInteractiveAuthentication;
	List<String> preferredAuthentications;
	Integer numberOfPasswordPrompts;
	final List<String> sendEnv = new ArrayList<String>();
	final Map<String, String> setEnv = new LinkedHashMap<String, String>();
	/** "~", "^X", one character, or "none" */
	String escapeChar;
	/** QUIET, FATAL, ERROR, INFO, VERBOSE, DEBUG... */
	String logLevel;
	String ciphers;
	String macs;
	String kexAlgorithms;
	String hostKeyAlgorithms;
	String hostKeyAlias;

	// ------------------------------------------------------------------ the command line

	/**
	 * Read OpenSSH's command line: ssh [options] [user@]host [options] [command...]. Options
	 * may be grouped (-tt, -vvv, -At) and take their argument joined (-p2222) or separate
	 * (-p 2222); after the host they end at the first word that isn't one (the command), or --.
	 */
	static SshOptions parse(String... args) throws UsageException {
		SshOptions o = new SshOptions();
		String target = null;
		int i = 0;
		// As OpenSSH: options before and after the host, until the command (or --)
		while( i < args.length ) {
			String a = args[i];
			if( a.equals("--help") ) {
				o.help = true;
				return o;
			}
			if( a.equals("--") ) {
				i++;
				if( target == null && i < args.length ) {
					target = args[i++];
				}
				break;
			}
			if( !a.startsWith("-") || a.length() == 1 ) {
				if( target != null ) {
					break;
				}
				target = a;
				i++;
				continue;
			}
			i++;
			for (int j = 1; j < a.length(); j++) {
				char c = a.charAt(j);
				if( WITH_ARGUMENT.indexOf(c) >= 0 ) {
					String value;
					if( j+1 < a.length() ) {
						value = a.substring(j+1);
					} else if( i < args.length ) {
						value = args[i++];
					} else {
						throw new UsageException("option requires an argument -- "+c);
					}
					o.option(c, value);
					break;
				} else if( FLAGS.indexOf(c) >= 0 ) {
					o.flag(c);
				} else if( c == 'h' ) {
					o.help = true;
					return o;
				} else {
					throw new UsageException("unknown option -- "+c);
				}
			}
		}
		if( o.showVersion || o.help ) {
			return o;
		}
		if( target == null ) {
			throw new UsageException("no host given");
		}
		int at = target.lastIndexOf('@');
		if( at >= 0 ) {
			if( o.user == null ) {
				o.user = target.substring(0, at);
			}
			target = target.substring(at+1);
		}
		if( target.startsWith("ssh://") ) {
			throw new UsageException("ssh:// URLs are not supported");
		}
		if( target.isEmpty() ) {
			throw new UsageException("no host given");
		}
		o.host = target;
		if( i < args.length ) {
			StringBuilder cmd = new StringBuilder();
			for (; i < args.length; i++) {
				if( cmd.length() > 0 ) {
					cmd.append(' ');
				}
				cmd.append(args[i]);
			}
			o.command = cmd.toString();
		}
		if( o.subsystem && o.command == null ) {
			throw new UsageException("-s needs the subsystem's name, e.g. ssh -s host sftp");
		}
		return o;
	}

	private void flag(char c) throws UsageException {
		switch (c) {
		case 'A': setIfUnset("forwardagent", "yes"); break;
		case 'a': setIfUnset("forwardagent", "no"); break;
		case 'C': if( compression == null ) compression = Boolean.TRUE; break;
		case 'N': noCommand = true; break;
		case 'n': stdinNull = true; break;
		case 'q': if( logLevel == null ) logLevel = "QUIET"; break;
		case 's': subsystem = true; break;
		case 'T': if( requestTty == null ) requestTty = "no"; break;
		case 't':
			ttyFlags++;
			if( requestTty == null || requestTty.equals("yes") ) {
				requestTty = ttyFlags > 1 ? "force" : "yes";
			}
			break;
		case 'V': showVersion = true; break;
		case 'v': verbose++; break;
		// Nothing to do: X11 and GSSAPI are not supported, and not using them is what these ask
		case 'x': case 'k': break;
		default:
			throw new UsageException("option -"+c+" is not supported by this client");
		}
	}

	private void option(char c, String value) throws UsageException {
		switch (c) {
		case 'c': setIfUnset("ciphers", value); break;
		case 'e': setIfUnset("escapechar", value); break;
		case 'F': configFile = value; break;
		case 'i': identityFiles.add(value); break;
		case 'L': localForwards.add(parseForward(value)); break;
		case 'l': if( user == null ) user = value; break;
		case 'm': setIfUnset("macs", value); break;
		case 'o': setOption(value); break;
		case 'p': setIfUnset("port", value); break;
		case 'R': remoteForwards.add(parseForward(value)); break;
		default:
			throw new UsageException("option -"+c+" is not supported by this client");
		}
	}

	/** -o "Keyword value" or -o Keyword=value */
	private void setOption(String text) throws UsageException {
		List<String> words = tokenize(text);
		if( words.isEmpty() ) {
			throw new UsageException("bad -o option: "+text);
		}
		String key = words.get(0).toLowerCase(Locale.ROOT);
		if( !set(key, words.subList(1, words.size())) && !isIgnored(key) ) {
			throw new UsageException("-o "+words.get(0)+" is not supported by this client");
		}
	}

	private void setIfUnset(String key, String value) throws UsageException {
		set(key, Arrays.asList(value));
	}

	// ------------------------------------------------------------------ settings

	/**
	 * Use a setting unless it already has a value (a list setting adds to its values).
	 *
	 * @param key the ssh_config keyword in lower case
	 * @param args its arguments
	 * @return false for a keyword this client doesn't know (or doesn't support)
	 */
	boolean set(String key, List<String> args) throws UsageException {
		String v = args.isEmpty() ? null : args.get(0);
		if( v == null && !key.equals("sendenv") && !key.equals("setenv") ) {
			throw new UsageException("missing argument for "+key);
		}
		switch (key) {
		case "hostname": if( hostName == null ) hostName = v; return true;
		case "user": if( user == null ) user = v; return true;
		case "port": if( port == null ) port = number(key, v, 1, 65535); return true;
		case "identityfile": identityFiles.add(v); return true;
		case "certificatefile": certificateFiles.add(v); return true;
		case "identitiesonly": if( identitiesOnly == null ) identitiesOnly = yesNo(key, v); return true;
		case "identityagent": if( identityAgent == null ) identityAgent = v; return true;
		case "stricthostkeychecking":
			if( strictHostKeyChecking == null ) {
				String s = v.toLowerCase(Locale.ROOT);
				switch (s) {
				case "yes": case "no": case "ask": case "accept-new": strictHostKeyChecking = s; break;
				case "off": strictHostKeyChecking = "no"; break;
				default: throw new UsageException("bad StrictHostKeyChecking: "+v);
				}
			}
			return true;
		case "userknownhostsfile": if( userKnownHostsFiles == null ) userKnownHostsFiles = new ArrayList<String>(args); return true;
		case "globalknownhostsfile": if( globalKnownHostsFiles == null ) globalKnownHostsFiles = new ArrayList<String>(args); return true;
		case "hashknownhosts": if( hashKnownHosts == null ) hashKnownHosts = yesNo(key, v); return true;
		case "hostkeyalias": if( hostKeyAlias == null ) hostKeyAlias = v; return true;
		case "forwardagent": if( forwardAgent == null ) forwardAgent = v; return true;
		case "localforward": localForwards.add(parseForward(String.join(":", args))); return true;
		case "remoteforward": remoteForwards.add(parseForward(String.join(":", args))); return true;
		case "exitonforwardfailure": if( exitOnForwardFailure == null ) exitOnForwardFailure = yesNo(key, v); return true;
		case "serveraliveinterval": if( serverAliveInterval == null ) serverAliveInterval = number(key, v, 0, Integer.MAX_VALUE); return true;
		case "serveralivecountmax": if( serverAliveCountMax == null ) serverAliveCountMax = number(key, v, 1, Integer.MAX_VALUE); return true;
		case "connecttimeout": if( connectTimeout == null ) connectTimeout = number(key, v, 0, Integer.MAX_VALUE); return true;
		case "compression": if( compression == null ) compression = yesNo(key, v); return true;
		case "requesttty":
			if( requestTty == null ) {
				String s = v.toLowerCase(Locale.ROOT);
				if( !Arrays.asList("yes", "no", "force", "auto").contains(s) ) {
					throw new UsageException("bad RequestTTY: "+v);
				}
				requestTty = s;
			}
			return true;
		case "batchmode": if( batchMode == null ) batchMode = yesNo(key, v); return true;
		case "passwordauthentication": if( passwordAuthentication == null ) passwordAuthentication = yesNo(key, v); return true;
		case "pubkeyauthentication": if( pubkeyAuthentication == null ) pubkeyAuthentication = yesNo(key, v); return true;
		case "kbdinteractiveauthentication":
		case "challengeresponseauthentication":
			if( kbdInteractiveAuthentication == null ) kbdInteractiveAuthentication = yesNo(key, v);
			return true;
		case "preferredauthentications":
			if( preferredAuthentications == null ) preferredAuthentications = Arrays.asList(v.split(","));
			return true;
		case "numberofpasswordprompts": if( numberOfPasswordPrompts == null ) numberOfPasswordPrompts = number(key, v, 0, 100); return true;
		case "sendenv":
			for (String a : args) {
				if( a.startsWith("-") ) {
					sendEnv.remove(a.substring(1));
				} else {
					sendEnv.add(a);
				}
			}
			return true;
		case "setenv":
			for (String a : args) {
				int eq = a.indexOf('=');
				if( eq <= 0 ) {
					throw new UsageException("bad SetEnv: "+a);
				}
				setEnv.putIfAbsent(a.substring(0, eq), a.substring(eq+1));
			}
			return true;
		case "escapechar": if( escapeChar == null ) escapeChar = checkEscape(v); return true;
		case "loglevel": if( logLevel == null ) logLevel = v.toUpperCase(Locale.ROOT); return true;
		case "ciphers": if( ciphers == null ) ciphers = v; return true;
		case "macs": if( macs == null ) macs = v; return true;
		case "kexalgorithms": if( kexAlgorithms == null ) kexAlgorithms = v; return true;
		case "hostkeyalgorithms": if( hostKeyAlgorithms == null ) hostKeyAlgorithms = v; return true;
		default:
			return false;
		}
	}

	/** ssh_config keywords that are read but change nothing here (they are about features this client doesn't have, or are only advice) */
	static boolean isIgnored(String key) {
		switch (key) {
		case "addkeystoagent": case "addressfamily": case "canonicalizehostname": case "canonicaldomains":
		case "canonicalizefallbacklocal": case "canonicalizemaxdots": case "canonicalizepermittedcnames":
		case "checkhostip": case "controlmaster": case "controlpath": case "controlpersist":
		case "forwardx11": case "forwardx11trusted": case "forwardx11timeout": case "gssapiauthentication":
		case "gssapidelegatecredentials": case "hostbasedauthentication": case "ipqos": case "tcpkeepalive":
		case "updatehostkeys": case "usekeychain": case "verifyhostkeydns": case "visualhostkey":
		case "xauthlocation": case "enablesshkeysign": case "fingerprinthash":
		case "pubkeyacceptedalgorithms": case "pubkeyacceptedkeytypes": case "casignaturealgorithms":
		case "stdinnull": case "sessiontype": case "forkafterauthentication": case "obscurekeystroketiming":
		case "requiredrsasize": case "warnweakcrypto": case "gatewayports": case "nohostauthenticationforlocalhost":
		case "streamlocalbindmask": case "streamlocalbindunlink": case "rekeylimit": case "securitykeyprovider":
		case "pkcs11provider": case "revokedhostkeys": case "permitremoteopen": case "clearallforwardings":
		case "bindaddress": case "bindinterface": case "connectionattempts": case "kbdinteractivedevices":
		case "permitlocalcommand": case "localcommand": case "loglevelverbose": case "logverbose": case "tag":
			return true;
		default:
			return false;
		}
	}

	private static Boolean yesNo(String key, String v) throws UsageException {
		switch (v.toLowerCase(Locale.ROOT)) {
		case "yes": case "true": return Boolean.TRUE;
		case "no": case "false": return Boolean.FALSE;
		default: throw new UsageException("bad "+key+" value (yes or no): "+v);
		}
	}

	private static int number(String key, String v, int min, int max) throws UsageException {
		try {
			int n = Integer.parseInt(v.trim());
			if( n < min || n > max ) {
				throw new UsageException("bad "+key+": "+v);
			}
			return n;
		} catch (NumberFormatException e) {
			throw new UsageException("bad "+key+": "+v);
		}
	}

	private static String checkEscape(String v) throws UsageException {
		if( v.equals("none") || v.length() == 1 || (v.length() == 2 && v.charAt(0) == '^') ) {
			return v;
		}
		throw new UsageException("bad escape character: "+v);
	}

	/**
	 * [bind_address:]port:host:hostport, with IPv6 addresses in brackets.
	 */
	static Forward parseForward(String spec) throws UsageException {
		List<String> parts = new ArrayList<String>();
		StringBuilder b = new StringBuilder();
		boolean bracket = false;
		for (char c : spec.toCharArray()) {
			if( c == '[' && b.length() == 0 ) {
				bracket = true;
			} else if( c == ']' && bracket ) {
				bracket = false;
			} else if( c == ':' && !bracket ) {
				parts.add(b.toString());
				b.setLength(0);
			} else {
				b.append(c);
			}
		}
		parts.add(b.toString());
		if( parts.size() == 4 || parts.size() == 3 ) {
			try {
				int k = parts.size()-3;
				String bind = k == 0 ? null : parts.get(0);
				if( bind != null && (bind.isEmpty() || bind.equals("*")) ) {
					bind = "0.0.0.0";
				}
				int bindPort = Integer.parseInt(parts.get(k));
				int port = Integer.parseInt(parts.get(k+2));
				String host = parts.get(k+1);
				if( bindPort < 0 || bindPort > 65535 || port < 1 || port > 65535 || host.isEmpty() ) {
					throw new NumberFormatException();
				}
				return new Forward(bind, bindPort, host, port);
			} catch (NumberFormatException e) {
				// below
			}
		}
		throw new UsageException("bad forwarding specification '"+spec+"' (use [bind_address:]port:host:hostport)");
	}

	// ------------------------------------------------------------------ after the config files

	/** The defaults for what neither the command line nor a config file set */
	void finish() {
		if( hostName == null ) {
			hostName = host;
		} else {
			hostName = hostName.replace("%h", host).replace("%%", "%");
		}
		if( user == null ) {
			user = System.getProperty("user.name");
		}
		if( port == null ) {
			port = 22;
		}
		if( strictHostKeyChecking == null ) {
			strictHostKeyChecking = "ask";
		}
		if( userKnownHostsFiles == null ) {
			userKnownHostsFiles = Arrays.asList("~/.ssh/known_hosts", "~/.ssh/known_hosts2");
		}
		if( globalKnownHostsFiles == null ) {
			globalKnownHostsFiles = Arrays.asList("/etc/ssh/ssh_known_hosts", "/etc/ssh/ssh_known_hosts2");
		}
		if( requestTty == null ) {
			requestTty = "auto";
		}
		if( escapeChar == null ) {
			escapeChar = "~";
		}
		if( logLevel == null ) {
			logLevel = "INFO";
		}
		if( numberOfPasswordPrompts == null ) {
			numberOfPasswordPrompts = 3;
		}
		if( preferredAuthentications == null ) {
			preferredAuthentications = Arrays.asList("publickey", "keyboard-interactive", "password");
		}
		if( identityFiles.isEmpty() ) {
			identityFiles.addAll(DEFAULT_IDENTITIES);
			defaultIdentities = true;
		}
	}

	/** finish() used the default identity files (missing ones aren't worth a warning) */
	boolean defaultIdentities;

	boolean isQuiet() {
		return logLevel.equals("QUIET") || logLevel.equals("FATAL") || logLevel.equals("ERROR");
	}

	boolean isBatch() {
		return Boolean.TRUE.equals(batchMode);
	}

	/** The escape character, or -1 for none */
	int escapeCharacter() {
		if( escapeChar.equals("none") ) {
			return -1;
		}
		if( escapeChar.length() == 2 ) {
			return Character.toUpperCase(escapeChar.charAt(1)) & 0x1f;
		}
		return escapeChar.charAt(0);
	}

	/**
	 * Expand ~ and OpenSSH's tokens: %% %d (home) %h (host name) %n (host as typed) %p (port)
	 * %r (remote user) %u (local user) %l (this host's name).
	 */
	String expand(String path) {
		String home = System.getProperty("user.home");
		if( path.equals("~") ) {
			path = home;
		} else if( path.startsWith("~/") ) {
			path = home+path.substring(1);
		}
		if( path.indexOf('%') < 0 ) {
			return path;
		}
		StringBuilder b = new StringBuilder();
		for (int i = 0; i < path.length(); i++) {
			char c = path.charAt(i);
			if( c != '%' || i+1 == path.length() ) {
				b.append(c);
				continue;
			}
			char t = path.charAt(++i);
			switch (t) {
			case '%': b.append('%'); break;
			case 'd': b.append(home); break;
			case 'h': b.append(hostName == null ? host : hostName); break;
			case 'n': b.append(host); break;
			case 'p': b.append(port == null ? 22 : port); break;
			case 'r': b.append(user); break;
			case 'u': b.append(System.getProperty("user.name")); break;
			case 'l': b.append(localHostName()); break;
			default: b.append('%').append(t);
			}
		}
		return b.toString();
	}

	private static String localHostName() {
		try {
			String n = InetAddress.getLocalHost().getHostName();
			int dot = n.indexOf('.');
			return dot > 0 ? n.substring(0, dot) : n;
		} catch (java.io.IOException e) {
			return "localhost";
		}
	}

	File file(String path) {
		return new File(expand(path));
	}

	// ------------------------------------------------------------------ helpers

	/**
	 * Split a config line or -o value into words: blanks separate, one "=" may separate the
	 * keyword from its value, and "double quotes" keep blanks in a word.
	 */
	static List<String> tokenize(String line) {
		List<String> ret = new ArrayList<String>();
		StringBuilder b = new StringBuilder();
		boolean quoted = false;
		boolean any = false;
		boolean equalsUsed = false;
		for (int i = 0; i < line.length(); i++) {
			char c = line.charAt(i);
			if( c == '"' ) {
				quoted = !quoted;
				any = true;
			} else if( !quoted && (Character.isWhitespace(c)
					|| (c == '=' && !equalsUsed && (ret.isEmpty() || (ret.size() == 1 && !any)))) ) {
				if( c == '=' ) {
					equalsUsed = true;
				}
				if( any ) {
					ret.add(b.toString());
					b.setLength(0);
					any = false;
				}
			} else {
				b.append(c);
				any = true;
			}
		}
		if( any ) {
			ret.add(b.toString());
		}
		return ret;
	}
}
