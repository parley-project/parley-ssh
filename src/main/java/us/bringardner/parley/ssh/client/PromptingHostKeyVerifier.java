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
import java.io.PrintStream;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.List;

import us.bringardner.parley.ssh.algorithms.SshCertificate;
import us.bringardner.parley.ssh.algorithms.SshPublicKeys;

/**
 * {@link Ssh}'s host key check, as OpenSSH's StrictHostKeyChecking: the keys are looked up in
 * the user's known_hosts files (new keys are added to the first) and the global ones (read only).
 * A key that doesn't match the one known, or is revoked, is always refused. An unknown host is
 * refused ("yes"), added ("accept-new", "no") or the user is asked ("ask").
 *
 * @author Tony Bringardner
 */
final class PromptingHostKeyVerifier implements IHostKeyVerifier {

	private static final String BANNER =
			"@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@";

	private final List<KnownHosts> files;
	private final KnownHosts addTo;
	private final String mode;
	private final CliTerminal terminal;
	private final boolean batch;
	private final boolean quiet;
	private volatile boolean failed;
	/** HostKeyAlias: the name keys are looked up and saved under, instead of the host's */
	private volatile String alias;

	/**
	 * @param user the user's known_hosts files, new hosts go to the first
	 * @param global the system's files
	 * @param mode yes, no, ask or accept-new
	 * @param batch never ask (an unknown host is refused if mode is "ask")
	 */
	PromptingHostKeyVerifier(List<File> user, List<File> global, boolean hash, String mode, CliTerminal terminal, boolean batch, boolean quiet) throws IOException {
		this.files = new ArrayList<KnownHosts>();
		KnownHosts first = null;
		for (File f : user) {
			if( first == null || f.isFile() ) {
				KnownHosts k = new KnownHosts(f);
				k.setHashNewHosts(hash);
				files.add(k);
				if( first == null ) {
					first = k;
				}
			}
		}
		for (File f : global) {
			if( f.isFile() ) {
				try {
					files.add(new KnownHosts(f));
				} catch (IOException e) {
					// not readable: as if it weren't there
				}
			}
		}
		this.addTo = first;
		this.mode = mode;
		this.terminal = terminal;
		this.batch = batch;
		this.quiet = quiet;
	}

	void setAlias(String alias) {
		this.alias = alias;
	}

	/** @return true if a host key was refused (and why was reported) */
	boolean failed() {
		return failed;
	}

	@Override
	public boolean verify(String host, int port, PublicKey key) throws IOException {
		String a = alias;
		boolean ret = a == null ? check(host, port, key) : check(a, 22, key);
		if( !ret ) {
			failed = true;
		}
		return ret;
	}

	private boolean check(String host, int port, PublicKey key) throws IOException {
		PrintStream err = terminal.err();
		String name = KnownHosts.hostName(host, port);
		String type = SshPublicKeys.keyType(key);
		String fp = SshPublicKeys.fingerprint(key);
		// As OpenSSH, all the files together: a revoked key is refused wherever it is marked; a key
		// any file has for the host is trusted; otherwise a different key of the same type is a change
		boolean trusted = false;
		boolean otherTypes = false;
		KnownHosts changedIn = null;
		for (KnownHosts k : files) {
			switch (k.check(host, port, key)) {
			case REVOKED:
				err.println(BANNER);
				err.println("@       WARNING: REVOKED HOST KEY DETECTED!               @");
				err.println(BANNER);
				err.println("The "+type+" host key for "+name+" is marked as revoked.");
				err.println("This could mean that a stolen key is being used to");
				err.println("impersonate this host.");
				return false;
			case TRUSTED:
				trusted = true;
				break;
			case CHANGED:
				if( changedIn == null ) {
					changedIn = k;
				}
				break;
			case OTHER_TYPES_KNOWN:
				otherTypes = true;
				break;
			default:
				break;
			}
		}
		if( trusted ) {
			return true;
		}
		if( changedIn != null ) {
			err.println(BANNER);
			err.println("@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @");
			err.println(BANNER);
			err.println("IT IS POSSIBLE THAT SOMEONE IS DOING SOMETHING NASTY!");
			err.println("Someone could be eavesdropping on you right now (man-in-the-middle attack)!");
			err.println("It is also possible that a host key has just been changed.");
			err.println("The fingerprint for the "+type+" key sent by the remote host is");
			err.println(fp+".");
			err.println("Please contact your system administrator.");
			err.println("Add correct host key in "+changedIn.getFile()+" to get rid of this message.");
			err.println("Host key for "+name+" has changed and you have requested strict checking.");
			return false;
		}
		if( mode.equals("yes") ) {
			err.println("No "+type+" host key is known for "+name+" and you have requested strict checking.");
			return false;
		}
		if( otherTypes ) {
			// Not added without asking: an attacker could offer a key type the host doesn't have
			err.println("Warning: the "+type+" host key for '"+name+"' differs from the key(s) of other types known for it.");
			if( !mode.equals("ask") ) {
				return false;
			}
		}
		if( mode.equals("ask") ) {
			if( batch ) {
				err.println("No "+type+" host key is known for "+name+" and BatchMode is on.");
				return false;
			}
			err.println("The authenticity of host '"+name+"' can't be established.");
			err.println(type+" key fingerprint is "+fp+".");
			err.println("This key is not known by any other names.");
			String q = "Are you sure you want to continue connecting (yes/no/[fingerprint])? ";
			while( true ) {
				char[] a = terminal.prompt(q, true);
				if( a == null ) {
					return false;
				}
				String s = new String(a).trim();
				if( s.equalsIgnoreCase("yes") || s.equals(fp) ) {
					break;
				}
				if( s.equalsIgnoreCase("no") ) {
					return false;
				}
				q = "Please type 'yes', 'no' or the fingerprint: ";
			}
		}
		if( addTo != null ) {
			try {
				File f = addTo.getFile();
				if( f != null && f.getParentFile() != null && !f.getParentFile().isDirectory() ) {
					f.getParentFile().mkdirs();
				}
				addTo.add(host, port, key);
				if( !quiet ) {
					err.println("Warning: Permanently added '"+name+"' ("+type+") to the list of known hosts.");
				}
			} catch (IOException e) {
				err.println("Failed to add the host to the list of known hosts ("+addTo.getFile()+"): "+e.getMessage());
			}
		}
		return true;
	}

	@Override
	public List<String> getKnownKeyTypes(String host, int port) {
		if( alias != null ) {
			host = alias;
			port = 22;
		}
		List<String> ret = new ArrayList<String>();
		for (KnownHosts k : files) {
			for (String t : k.getKnownKeyTypes(host, port)) {
				if( !ret.contains(t) ) {
					ret.add(t);
				}
			}
		}
		return ret;
	}

	@Override
	public boolean verifyCertificate(String host, int port, SshCertificate certificate) throws IOException {
		String a = alias;
		for (KnownHosts k : files) {
			if( a == null ? k.verifyCertificate(host, port, certificate) : k.verifyCertificate(a, 22, certificate) ) {
				return true;
			}
		}
		// Not trusted as a certificate: as OpenSSH, check the certified key as a plain key
		return verify(host, port, certificate.getPublicKey());
	}

	/** For messages: the files looked in */
	List<File> getFiles() {
		List<File> ret = new ArrayList<File>();
		for (KnownHosts k : files) {
			ret.add(k.getFile());
		}
		return ret;
	}

	static List<File> files(SshOptions o, List<String> paths) {
		List<File> ret = new ArrayList<File>();
		for (String p : paths) {
			if( !p.equalsIgnoreCase("none") ) {
				ret.add(o.file(p));
			}
		}
		return ret;
	}
}
