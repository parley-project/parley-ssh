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
import java.nio.file.Files;
import java.nio.file.attribute.PosixFilePermissions;

import us.bringardner.parley.net.server.ServerMain;

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
 * Logins: passwords through the access control list ({@code parley.ssh.authenticationProvider};
 * none without it), keys in each user's HOMES/USER/.ssh/authorized_keys, and user certificates
 * signed by a trusted CA. SFTP (when parley-files is on the class path) puts each user in their
 * home: the access control list's {@code userRoot} parameter, as for FTP, else HOMES/USER.
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

	private final File confDir;
	private final boolean windows;
	private final boolean mac;

	ServiceSetup(File confDir, boolean windows, boolean mac) {
		this.confDir = confDir;
		this.windows = windows;
		this.mac = mac;
	}

	/** For this machine: Parley's administrator folder (ServerMain.confDir) and the operating system */
	static ServiceSetup forThisMachine() {
		String os = System.getProperty("os.name", "").toLowerCase();
		return new ServiceSetup(ServerMain.confDir(), os.startsWith("windows"), os.startsWith("mac"));
	}

	File getConfDir() {
		return confDir;
	}

	File defaultHomes() {
		if( windows ) {
			return new File(System.getenv().getOrDefault("SystemDrive", "C:")+"\\Users");
		}
		return new File(mac ? "/Users" : "/home");
	}

	/**
	 * Set up the server from its settings: the port, host keys, logins and SFTP.
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
			File keys = new File(confDir, HOST_KEY_FOLDER);
			ownerOnlyFolder(keys);
			server.setHostKeyProvider(HostKeyProviders.generated(keys));
		}

		String homesSetting = setting(server, PROPERTY_HOMES);
		File homes = homesSetting != null ? new File(homesSetting) : defaultHomes();

		IPublicKeyAuthenticator keys = AuthorizedKeysAuthenticator.forHomes(homes);
		String caSetting = setting(server, PROPERTY_TRUSTED_USER_CA_KEYS);
		File cas = caSetting != null ? new File(caSetting) : new File(new File(confDir, HOST_KEY_FOLDER), TRUSTED_USER_CA_KEYS_FILE);
		if( cas.isFile() ) {
			keys = keys.or(UserCertificateAuthenticator.fromFile(cas));
			server.logInfo("User certificates signed by the CAs in "+cas);
		} else if( caSetting != null ) {
			throw new IOException(SshServer.PROPERTY_PREFIX+"."+PROPERTY_TRUSTED_USER_CA_KEYS+": no such file: "+cas);
		}
		server.setPublicKeyAuthenticator(keys);
		server.logInfo("authorized_keys in "+homes+File.separator+"USER"+File.separator+".ssh");
		if( server.getAccessControl() == null ) {
			server.logInfo("No access control list ("+SshServer.PROPERTY_PREFIX+".authenticationProvider): no password logins");
		}

		if( parleyFilesPresent() ) {
			SftpSetup.add(server, homes);
			server.logInfo("SFTP: each user in their userRoot, else "+homes+File.separator+"USER");
		} else {
			server.logInfo("No SFTP: parley-files is not on the class path");
		}
	}

	private static String setting(SshServer server, String name) {
		String v = server.getProperty(server.propertyName(name));
		return v == null || v.trim().isEmpty() ? null : v.trim();
	}

	private static boolean parleyFilesPresent() {
		try {
			Class.forName("us.bringardner.parley.files.FileSource", false, ServiceSetup.class.getClassLoader());
			return true;
		} catch (ClassNotFoundException | LinkageError e) {
			return false;
		}
	}

	/** Make the folder (rwx------ where the file system has POSIX permissions) */
	private static void ownerOnlyFolder(File dir) throws IOException {
		if( dir.isDirectory() ) {
			return;
		}
		if( !dir.mkdirs() && !dir.isDirectory() ) {
			throw new IOException("Can't make the host key folder "+dir);
		}
		try {
			Files.setPosixFilePermissions(dir.toPath(), PosixFilePermissions.fromString("rwx------"));
		} catch (UnsupportedOperationException e) {
			// (Windows: the folder's ACL comes from its parent, %ProgramData%\Parley)
		}
	}
}
