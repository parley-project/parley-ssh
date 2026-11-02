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
package us.bringardner.parley.ssh.sftp.server;

import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.Map;

import us.bringardner.parley.files.FileSource;
import us.bringardner.parley.net.lock.LockDomain;
import us.bringardner.parley.net.lock.StoreClaim;
import us.bringardner.parley.net.lock.StoreLocks;
import us.bringardner.parley.ssh.server.CommandEnvironment;
import us.bringardner.parley.ssh.server.ICommand;
import us.bringardner.parley.ssh.server.ISubsystemFactory;

/**
 * The "sftp" subsystem: an SFTP version 3 server (what OpenSSH's sftp, scp -s, FileZilla,
 * WinSCP, JSch and MINA speak) on any parley-files {@link FileSource}: the local disk,
 * memory, JDBC, another SFTP server...
 *
 * <pre>
 * server.addSubsystem(new SftpSubsystemFactory(env -&gt;
 *         new FileProxyFactory().createFileSource("/srv/sftp/"+env.getUser())));
 * </pre>
 *
 * The server claims each store its sessions use (parley-net's {@link StoreLocks}, shared as
 * {@value SftpServer#SHARED_STORE_PROPERTY} says), once, the first time a session needs it, and
 * keeps the claim until {@link #close()} ({@link us.bringardner.parley.ssh.server.SshServer} closes
 * its subsystems when it stops). Its sessions share the claim: any number of them, from one client
 * or many, run at once. A store another server has alone refuses the session.
 *
 * @author Tony Bringardner
 */
public class SftpSubsystemFactory implements ISubsystemFactory, AutoCloseable {

	private final ISftpRootProvider roots;
	private volatile boolean readOnly;
	/** The stores claimed, each with the lock domain kept open for it */
	private final Map<LockDomain, StoreClaim> claims = new LinkedHashMap<LockDomain, StoreClaim>();

	/**
	 * @param roots each user's root directory
	 */
	public SftpSubsystemFactory(ISftpRootProvider roots) {
		this.roots = roots;
	}

	/**
	 * @return every user gets the same root
	 */
	public static SftpSubsystemFactory forRoot(FileSource root) {
		return new SftpSubsystemFactory(env -> root);
	}

	@Override
	public String getName() {
		return "sftp";
	}

	@Override
	public ICommand create(CommandEnvironment env) throws IOException {
		FileSource root = roots.getRoot(env);
		if( root == null ) {
			return null;
		}
		if( !root.isDirectory() ) {
			throw new IOException("SFTP root is not a directory: "+root);
		}
		claim(root);
		return new SftpServer(root, readOnly);
	}

	/** Claim root's store for this server if it hasn't been yet. */
	private void claim(FileSource root) throws IOException {
		StoreLocks locks = StoreLocks.get();
		LockDomain domain = locks.acquire(root, StoreLocks.sharing(SftpServer.SHARED_STORE_PROPERTY));
		boolean keep = false;
		try {
			synchronized (claims) {
				if( !claims.containsKey(domain) ) {
					claims.put(domain, domain.claimStore(StoreLocks.serverId(SftpServer.SERVER_ID_PROPERTY, "sftp", 0)));
					keep = true;   // this acquire stays open with the claim, until close()
				}
			}
		} finally {
			if( !keep ) {
				locks.release(domain);
			}
		}
	}

	/** @return how many stores this server has claimed (for tests) */
	public int getClaimedStores() {
		synchronized (claims) {
			return claims.size();
		}
	}

	/**
	 * Let go of the stores' claims, after the sessions have ended (SshServer does this when it
	 * stops). A server started again claims them again with its first sessions.
	 */
	@Override
	public void close() {
		synchronized (claims) {
			for (Map.Entry<LockDomain, StoreClaim> e : claims.entrySet()) {
				try {
					e.getValue().close();
				} finally {
					StoreLocks.get().release(e.getKey());
				}
			}
			claims.clear();
		}
	}

	public boolean isReadOnly() {
		return readOnly;
	}

	/**
	 * @param readOnly true to refuse every change (writes, removes, renames, setstat...)
	 */
	public void setReadOnly(boolean readOnly) {
		this.readOnly = readOnly;
	}
}
