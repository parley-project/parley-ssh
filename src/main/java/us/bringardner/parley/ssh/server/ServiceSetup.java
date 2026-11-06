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

import java.io.IOException;

import us.bringardner.parley.files.FileSource;
import us.bringardner.parley.net.server.ServerMain;
import us.bringardner.parley.ssh.SshFiles;

/**
 * How {@link SshServer#main(String[])} sets up a server run as a service (systemd, launchd, a
 * Windows service): where its settings, host keys and users' homes are, and how users log in.
 * Every value comes from a {@code parley.ssh.*} setting when there is one, else from the
 * defaults below.
 *
 * <pre>
 *   settings file      parley.ssh.configFile         CONF/parley-ssh.properties, when it is there
 *   host keys          parley.ssh.hostKeyDir         CONF/ssh (made, readable by the owner only)
 *   port               parley.ssh.port               22
 *   users' homes       parley.ssh.homes              /home (macOS /Users, Windows C:\Users)
 *   trusted user CAs   parley.ssh.trustedUserCaKeys  CONF/ssh/trusted_user_ca_keys, when it is there
 * </pre>
 *
 * CONF is the folder of Parley's administrator file: /etc/parley (Windows
 * %ProgramData%\Parley), or the folder of the file the PARLEY_CONF environment variable names.
 * <p>
 * Logins: the user registry ({@code parley.ssh.authenticationProvider}, a parley-iam
 * {@code UserRegistry}; required) says who the users are and what they may do, and checks
 * passwords; keys are in each user's HOMES/USER/.ssh/authorized_keys, and user certificates
 * are signed by a trusted CA (a key or certificate logs in a user the registry knows). SFTP
 * puts each user in their home: the principal's {@code userRoot} attribute, as for FTP, else
 * HOMES/USER.
 * <p>
 * Every session runs as the account the service runs as, whoever logged in.
 *
 * @author Tony Bringardner
 */
final class ServiceSetup {

	static final String PROPERTY_CONFIG_FILE = "configFile";
	static final String PROPERTY_HOMES = "homes";
	static final String PROPERTY_TRUSTED_USER_CA_KEYS = "trustedUserCaKeys";
	static final String CONFIG_FILE_NAME = "parley-ssh.properties";
	static final String HOST_KEY_FOLDER = "ssh";
	static final String TRUSTED_USER_CA_KEYS_FILE = "trusted_user_ca_keys";
	static final int DEFAULT_PORT = 22;

	private final FileSource confDir;
	private final boolean windows;
	private final boolean mac;

	ServiceSetup(FileSource confDir, boolean windows, boolean mac) {
		this.confDir = confDir;
		this.windows = windows;
		this.mac = mac;
	}

	/** For this machine: Parley's administrator folder (ServerMain.confDir) and the operating system */
	static ServiceSetup forThisMachine() throws IOException {
		String os = System.getProperty("os.name", "").toLowerCase();
		return new ServiceSetup(SshFiles.local(ServerMain.confDir().getPath()), os.startsWith("windows"), os.startsWith("mac"));
	}

	FileSource getConfDir() {
		return confDir;
	}

	FileSource defaultHomes() throws IOException {
		if( windows ) {
			return SshFiles.local(System.getenv().getOrDefault("SystemDrive", "C:")+"\\Users");
		}
		return SshFiles.local(mac ? "/Users" : "/home");
	}

	/**
	 * Set up the server from its settings: the port, host keys, logins and SFTP.
	 *
	 * @throws IOException when a setting is wrong, or there is no user registry (nobody could log in)
	 */
	void configure(SshServer server) throws IOException {
		String port = setting(server, "port");
		if( port != null ) {
			try {
				server.setPort(Integer.parseInt(port));
			} catch (NumberFormatException e) {
				throw new IOException(SshServer.PROPERTY_PREFIX+".port is not a number: "+port);
			}
		}

		if( setting(server, SshServer.PROPERTY_HOST_KEY_DIR) == null && server.getKeyStoreFileName() == null ) {
			FileSource keys = confDir.getChild(HOST_KEY_FOLDER);
			ownerOnlyFolder(keys);
			server.setHostKeyProvider(HostKeyProviders.generated(keys));
		}

		String homesSetting = setting(server, PROPERTY_HOMES);
		FileSource homes = homesSetting != null ? SshFiles.local(homesSetting) : defaultHomes();
		char sep = homes.getFileSourceFactory().getSeparatorChar();

		IPublicKeyAuthenticator keys = AuthorizedKeysAuthenticator.forHomes(homes);
		String caSetting = setting(server, PROPERTY_TRUSTED_USER_CA_KEYS);
		FileSource cas = caSetting != null ? SshFiles.local(caSetting) : confDir.getChild(HOST_KEY_FOLDER).getChild(TRUSTED_USER_CA_KEYS_FILE);
		if( cas.isFile() ) {
			keys = keys.or(UserCertificateAuthenticator.fromFile(cas));
			server.logInfo("User certificates signed by the CAs in "+cas);
		} else if( caSetting != null ) {
			throw new IOException(SshServer.PROPERTY_PREFIX+"."+PROPERTY_TRUSTED_USER_CA_KEYS+": no such file: "+cas);
		}
		server.setPublicKeyAuthenticator(keys);
		server.logInfo("authorized_keys in "+homes+sep+"USER"+sep+".ssh");
		try {
			// a missing registry is an error (parley-iam: there are no built-in users)
			server.requireUserRegistry();
		} catch (IllegalStateException e) {
			throw new IOException(e.getMessage());
		}

		SftpSetup.add(server, homes);
		server.logInfo("SFTP: each user in their userRoot, else "+homes+sep+"USER");
	}

	private static String setting(SshServer server, String name) {
		String v = server.getProperty(server.propertyName(name));
		return v == null || v.trim().isEmpty() ? null : v.trim();
	}

	/** Make the folder (rwx------ where the file system has POSIX permissions) */
	private void ownerOnlyFolder(FileSource dir) throws IOException {
		if( dir.isDirectory() ) {
			return;
		}
		if( !dir.mkdirs() && !dir.isDirectory() ) {
			throw new IOException("Can't make the host key folder "+dir);
		}
		if( windows ) {
			// (Windows: the folder's ACL comes from its parent, %ProgramData%\Parley)
			return;
		}
		dir.setGroupReadable(false);
		dir.setGroupWritable(false);
		dir.setGroupExecutable(false);
		dir.setOtherReadable(false);
		dir.setOtherWritable(false);
		dir.setOtherExecutable(false);
		dir.setOwnerReadable(true);
		dir.setOwnerWritable(true);
		dir.setOwnerExecutable(true);
	}
}
