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
import java.security.KeyPair;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledThreadPoolExecutor;

import us.bringardner.parley.core.NamedThreadFactory;
import us.bringardner.parley.iam.AuthenticationResult;
import us.bringardner.parley.iam.Credential;
import us.bringardner.parley.iam.ParleyPrincipal;
import us.bringardner.parley.iam.StoredCredential;
import us.bringardner.parley.iam.StoredCredentialType;
import us.bringardner.parley.iam.UserRegistry;
import us.bringardner.parley.iam.UserRegistryUnavailableException;
import us.bringardner.parley.iam.credential.PasswordCredential;
import us.bringardner.parley.iam.credential.ProofCredential;
import us.bringardner.parley.net.nio.LineFrameDecoder;
import us.bringardner.parley.net.nio.NioServer;
import us.bringardner.parley.net.server.ServerMain;
import us.bringardner.parley.ssh.SshFiles;
import us.bringardner.parley.ssh.algorithms.SshAlgorithms;
import us.bringardner.parley.ssh.algorithms.SshCertificate;
import us.bringardner.parley.ssh.algorithms.SshPublicKeys;
import us.bringardner.parley.ssh.transport.SshTransport;

/**
 * An SSH server on the framework's non-blocking {@link NioServer}, so it is configured like
 * any Parley server (port, bindAddress, maxConnections, the key store settings...) and logs
 * users in with the same parley-iam user registry ({@code authenticationProvider} or
 * {@link #setUserRegistry}). Without a registry nobody can log in.
 * <p>
 * <b>What it runs</b> is up to the plug-ins: {@link #setCommandFactory(ICommandFactory)} for
 * exec, {@link #setShellFactory(IShellFactory)} (or the {@value #PROPERTY_SHELL_FACTORY}
 * property; fsh by default when it is on the class path) for an interactive shell,
 * {@link #addSubsystem(ISubsystemFactory)} for subsystems such as SFTP. Without them those
 * requests are refused. A user also needs the permission ("exec", "shell", the subsystem
 * name, or "forward"): the registry decides who holds it.
 * <p>
 * <b>Logging in</b>: password and keyboard-interactive send the password to the registry
 * (offered when it checks passwords); publickey checks the key with
 * {@link #setPublicKeyAuthenticator(IPublicKeyAuthenticator)} (e.g.
 * {@link AuthorizedKeysAuthenticator}) and takes the user from the registry; or any
 * {@link IServerAuthMethod}s. Every login goes through the session's authenticate, which
 * counts refused logins: at most {@link #setMaxLoginAttempts(int)}, each answered after
 * {@link #setLoginFailureDelay(int)}, within {@link #setLoginTimeLimit(int)} (OpenSSH's
 * defaults: 6 tries, 2 minutes; 250 ms delay).
 * <p>
 * <b>Host keys</b> come from {@link #setHostKeyProvider(IHostKeyProvider)}; else from the key
 * store when keyStoreName is set; else they are made once in the hostKeyDir property's
 * directory (default ".") like ssh-keygen -A.
 *
 * <pre>
 * SshServer server = new SshServer(2222);
 * server.setHostKeyProvider(HostKeyProviders.generated(SshFiles.local("/var/myapp/ssh")));
 * server.setPublicKeyAuthenticator(AuthorizedKeysAuthenticator.forHomes(SshFiles.local("/home")));
 * server.addSubsystem(new SftpSubsystemFactory(...));
 * server.startAndWait(10000);
 * </pre>
 *
 * @author Tony Bringardner
 */
public class SshServer extends NioServer {

	/** The prefix of an SSH server's properties (parley.ssh.port, parley.ssh.hostKeyDir ...). */
	public static final String PROPERTY_PREFIX = "parley.ssh";
	public static final String PROPERTY_HOST_KEY_DIR = "hostKeyDir";
	/**
	 * Class name of the {@link IShellFactory} to use (public no-argument constructor), or "none"
	 * for no shell; without it, fsh ({@value #DEFAULT_SHELL_FACTORY}) when it is on the class path
	 */
	public static final String PROPERTY_SHELL_FACTORY = "shellFactory";
	/**
	 * A program to run as the shell, with its arguments (split at blanks, "double quotes" keep blanks
	 * together), run by {@link ProcessShellFactory}: on a real pseudo terminal when the client asks for
	 * one and pty4j is on the class path, so it has job control. Used when no
	 * {@value #PROPERTY_SHELL_FACTORY} is set. For fsh as a separate program: "/opt/fsh/bin/fsh -i -l".
	 */
	public static final String PROPERTY_SHELL_COMMAND = "shellCommand";
	/** The shell used when none is configured and it is on the class path: fsh, the FileSource Shell */
	public static final String DEFAULT_SHELL_FACTORY = "us.bringardner.fsh.ssh.FshShellFactory";
	/** A KRL or list of public keys (OpenSSH's RevokedKeys): those keys and certificates can't log in */
	public static final String PROPERTY_REVOKED_KEYS = "revokedKeys";
	/** Like OpenSSH's MaxAuthTries: clients try each of their keys, and each refused key counts */
	public static final int DEFAULT_MAX_AUTH_TRIES = 6;
	/** Like OpenSSH's LoginGraceTime */
	public static final int DEFAULT_LOGIN_GRACE_TIME = 120000;
	/** Short, because refused keys are failures too */
	public static final int DEFAULT_AUTH_FAILURE_DELAY = 250;

	private final SecureRandom random = new SecureRandom();
	private final ExecutorService executor = Executors.newCachedThreadPool(NamedThreadFactory.numbered("SshServer-"));
	private final ScheduledExecutorService scheduler;
	private volatile SshAlgorithms algorithms = SshAlgorithms.defaults();
	private volatile String version = SshTransport.DEFAULT_VERSION;
	private volatile IHostKeyProvider hostKeyProvider;
	private volatile List<KeyPair> hostKeys = Collections.emptyList();
	private volatile List<SshCertificate> hostCertificates = Collections.emptyList();
	private volatile List<IServerAuthMethod> authMethods;
	private volatile IPublicKeyAuthenticator publicKeyAuthenticator;
	private volatile ICommandFactory commandFactory;
	private volatile IShellFactory shellFactory;
	private volatile us.bringardner.parley.ssh.keys.KeyRevocationList revokedKeys;
	private volatile boolean shellFactoryConfigured;
	private final Map<String, ISubsystemFactory> subsystems = new ConcurrentHashMap<String, ISubsystemFactory>();
	private volatile String banner;
	private volatile int maxChannelsPerSession = 10;
	private volatile IForwardingFilter forwardingFilter;
	private volatile boolean agentForwarding = true;
	private volatile boolean securityKeyTouchRequired;
	private volatile boolean securityKeyVerifyRequired;

	public SshServer() {
		this(22);
	}

	public SshServer(int port) {
		super(port);
		setPropertyPrefix(PROPERTY_PREFIX);
		ScheduledThreadPoolExecutor s = new ScheduledThreadPoolExecutor(1, new NamedThreadFactory("SshServer-scheduler"));
		s.setRemoveOnCancelPolicy(true);
		scheduler = s;
		setHandlerFactory(() -> new ServerSession(this));
		// The identification line; the transport then switches to its packet decoder
		setDecoderFactory(() -> new LineFrameDecoder(1024));
		// Logins (password hashing), commands and file access block: not on the selector threads
		setHandlerExecutor(executor);
		setMaxInputBuffer(2*1024*1024);
	}

	/**
	 * Run an SSH server as a service (systemd, launchd, a Windows service) until it is stopped, with
	 * {@link ServerMain#run}: settings from the command line and parley-ssh.properties in Parley's
	 * administrator folder (the command line wins), exit code 1 when it can't start, stopped with the
	 * process. {@link ServiceSetup} sets up the host keys, the logins (passwords through the user
	 * registry, each user's authorized_keys, trusted user certificates) and SFTP to each
	 * user's home.
	 */
	public static void main(String[] args) throws Exception {
		ServerMain.run("SshServer", args, PROPERTY_PREFIX+"."+ServiceSetup.PROPERTY_CONFIG_FILE, ServiceSetup.CONFIG_FILE_NAME, () -> {
			SshServer server = new SshServer(ServiceSetup.DEFAULT_PORT);
			server.setName("SshServer");
			ServiceSetup.forThisMachine().configure(server);
			return java.util.Collections.singletonList(ServerMain.service(server, "SshServer"));
		});
	}

	/**
	 * Read the host keys and the configured shell, then start.
	 *
	 * @throws IOException if there are no host keys (or they can't be read), the
	 * {@value #PROPERTY_SHELL_FACTORY} property names a class that can't be made, or the server doesn't start
	 */
	@Override
	public void startAndWait(long timeoutMillis) throws IOException {
		loadHostKeys();
		try {
			getShellFactory();
		} catch (IllegalStateException e) {
			throw new IOException(e.getMessage(), e.getCause());
		}
		super.startAndWait(timeoutMillis);
	}

	/**
	 * Read the host keys and the configured shell, then start; a problem with them is logged and
	 * the server doesn't start.
	 */
	@Override
	public synchronized void start() {
		if( hostKeys.isEmpty() ) {
			try {
				loadHostKeys();
			} catch (IOException e) {
				logError("Can't load the host keys, server "+getName()+" not started", e);
				return;
			}
		}
		try {
			getShellFactory();
		} catch (IllegalStateException e) {
			logError("Server "+getName()+" not started: "+e.getMessage());
			return;
		}
		super.start();
	}

	private synchronized void loadHostKeys() throws IOException {
		IHostKeyProvider p = hostKeyProvider;
		if( p == null ) {
			if( getKeyStoreFileName() != null ) {
				p = HostKeyProviders.fromKeyStore(this);
			} else {
				p = HostKeyProviders.generated(SshFiles.local(getProperty(propertyName(PROPERTY_HOST_KEY_DIR), ".")));
			}
		}
		List<KeyPair> keys = p.getHostKeys();
		if( keys == null || keys.isEmpty() ) {
			throw new IOException("No host keys");
		}
		List<SshCertificate> certs = new ArrayList<SshCertificate>();
		for (SshCertificate c : p.getHostCertificates()) {
			boolean ours = false;
			for (KeyPair kp : keys) {
				ours |= java.util.Arrays.equals(SshPublicKeys.encode(kp.getPublic()), c.getPublicKeyBlob());
			}
			if( c.getCertificateType() != SshCertificate.HOST || !ours ) {
				logWarn("Not using "+c+": "+(ours ? "not a host certificate" : "it is for none of the host keys"));
			} else {
				certs.add(c);
			}
		}
		hostKeys = Collections.unmodifiableList(new ArrayList<KeyPair>(keys));
		hostCertificates = Collections.unmodifiableList(certs);
		String revoked = getProperty(propertyName(PROPERTY_REVOKED_KEYS));
		if( revokedKeys == null && revoked != null && !revoked.trim().isEmpty() ) {
			revokedKeys = us.bringardner.parley.ssh.keys.KeyRevocationList.load(SshFiles.local(revoked.trim()));
		}
	}

	// ------------------------------------------------------------------ authentication

	/**
	 * @return the methods offered, in order: the ones set, else publickey (with a public key
	 * authenticator), then password and keyboard-interactive (when the user registry checks
	 * passwords)
	 */
	public List<IServerAuthMethod> getAuthMethods() {
		List<IServerAuthMethod> m = authMethods;
		if( m != null ) {
			return m;
		}
		List<IServerAuthMethod> ret = new ArrayList<IServerAuthMethod>();
		IPublicKeyAuthenticator pk = publicKeyAuthenticator;
		if( pk != null ) {
			ret.add(new PublicKeyAuthMethod(pk));
		}
		UserRegistry registry = getUserRegistry();
		if( registry != null && registry.supports(PasswordCredential.class, null) ) {
			ret.add(new PasswordAuthMethod());
			ret.add(new KeyboardInteractiveAuthMethod());
		}
		return Collections.unmodifiableList(ret);
	}

	public void setAuthMethods(List<IServerAuthMethod> methods) {
		this.authMethods = methods == null ? null : Collections.unmodifiableList(new ArrayList<IServerAuthMethod>(methods));
	}

	IServerAuthMethod findAuthMethod(String name) {
		for (IServerAuthMethod m : getAuthMethods()) {
			if( m.getName().equals(name) ) {
				return m;
			}
		}
		return null;
	}

	/** What an SSH public key proof is checked against: the registry keeps no SSH keys (see {@link #authenticate}) */
	private static final StoredCredential NO_REGISTRY_KEYS = new StoredCredential(StoredCredentialType.SSH_PUBLIC_KEYS, Collections.emptyList());

	/**
	 * As every Parley server, with one addition for SSH's public keys: a {@link ProofCredential}
	 * of {@link StoredCredentialType#SSH_PUBLIC_KEYS} ({@link PublicKeyAuthMethod}'s) is proven
	 * by its own verifier, which checks the key with the public key authenticator
	 * (authorized_keys, trusted certificate authorities) and the signature; the stored secret it
	 * is given is an empty list, since the user's keys are not the registry's. The user then
	 * comes from the user registry ({@link UserRegistry#findPrincipal(String)}): a key for a user
	 * the registry doesn't know is refused, and a registry that can't answer is UNAVAILABLE.
	 * Every other credential goes to the registry as the framework sends it.
	 *
	 * @throws IllegalStateException when the server has no user registry
	 */
	@Override
	public AuthenticationResult authenticate(Credential credential) {
		ProofCredential proof = publicKeyProof(credential);
		if( proof != null ) {
			return checkPublicKey(proof, true);
		}
		return super.authenticate(credential);
	}

	/**
	 * As {@link #authenticate}, without recording the outcome: for publickey's query
	 * (would this key do?).
	 *
	 * @throws IllegalStateException when the server has no user registry
	 */
	@Override
	public AuthenticationResult probe(Credential credential) {
		ProofCredential proof = publicKeyProof(credential);
		if( proof != null ) {
			return checkPublicKey(proof, false);
		}
		return super.probe(credential);
	}

	/** @return the credential when it is a proof of SSH public keys, else null */
	private static ProofCredential publicKeyProof(Credential credential) {
		if( credential instanceof ProofCredential ) {
			ProofCredential proof = (ProofCredential) credential;
			if( StoredCredentialType.SSH_PUBLIC_KEYS.equals(proof.getStoredType()) ) {
				return proof;
			}
		}
		return null;
	}

	private AuthenticationResult checkPublicKey(ProofCredential proof, boolean record) {
		UserRegistry registry = requireUserRegistry();
		String user = proof.getUser();
		AuthenticationResult result;
		try {
			boolean proven;
			try {
				proven = user != null && proof.getVerifier().verify(NO_REGISTRY_KEYS);
			} catch (IOException e) {
				logDebug("Can't check the key of "+user, e);
				proven = false;
			}
			if( !proven ) {
				result = AuthenticationResult.refused("publickey not accepted for "+user);
			} else {
				ParleyPrincipal principal = registry.findPrincipal(user);
				result = principal == null ? AuthenticationResult.refused("no user "+user)
						: AuthenticationResult.authenticated(principal, PublicKeyAuthMethod.NAME);
			}
		} catch (UserRegistryUnavailableException e) {
			result = AuthenticationResult.unavailable(e.getMessage());
		}
		if( record ) {
			registry.recordOutcome(user, result);
		}
		return result;
	}

	public IPublicKeyAuthenticator getPublicKeyAuthenticator() {
		return publicKeyAuthenticator;
	}

	public void setPublicKeyAuthenticator(IPublicKeyAuthenticator authenticator) {
		this.publicKeyAuthenticator = authenticator;
	}

	// ------------------------------------------------------------------ plug-ins

	public ICommandFactory getCommandFactory() {
		return commandFactory;
	}

	/**
	 * @param factory runs "exec" requests; null (default) refuses them
	 */
	public void setCommandFactory(ICommandFactory factory) {
		this.commandFactory = factory;
	}

	/**
	 * @return the factory set with {@link #setShellFactory(IShellFactory)}, else one made from
	 * the {@value #PROPERTY_SHELL_FACTORY} property, else fsh when it is on the class path
	 * (and it can be made), else null (shell requests are refused). The
	 * property "none" means no shell, even with fsh there.
	 * @throws IllegalStateException if the property names a class that can't be made
	 */
	public IShellFactory getShellFactory() {
		if( shellFactory == null && !shellFactoryConfigured ) {
			synchronized (this) {
				if( shellFactory == null && !shellFactoryConfigured ) {
					String tmp = getProperty(propertyName(PROPERTY_SHELL_FACTORY));
					if( tmp != null && tmp.trim().equalsIgnoreCase("none") ) {
						logInfo("No shell in server "+getName()+" (shellFactory=none)");
					} else if( tmp != null && !tmp.trim().isEmpty() ) {
						try {
							Class<?> c = Class.forName(tmp.trim());
							shellFactory = (IShellFactory) c.getDeclaredConstructor().newInstance();
						} catch (Exception e) {
							logError("Can't configure shell factory class='"+tmp+"'", e);
							throw new IllegalStateException("Can't configure shell factory class='"+tmp+"'", e);
						}
					} else if( shellCommandSetting() != null ) {
						List<String> line = splitCommandLine(shellCommandSetting());
						shellFactory = new ProcessShellFactory(null, line);
						logInfo("Server "+getName()+" runs "+line+" as its shell"+(ProcessCommandFactory.isPtySupported() ? ", on a pseudo terminal" : " (no pty4j: without a pseudo terminal)"));
					} else {
						shellFactory = defaultShellFactory();
						if( shellFactory == null ) {
							logInfo("No shell defined in server "+getName());
						} else {
							logInfo("Server "+getName()+" uses fsh as its shell (shellFactory=none turns it off)");
						}
					}
					shellFactoryConfigured = true;
				}
			}
		}
		return shellFactory;
	}

	private String shellCommandSetting() {
		String tmp = getProperty(propertyName(PROPERTY_SHELL_COMMAND));
		return tmp == null || tmp.trim().isEmpty() ? null : tmp.trim();
	}

	/**
	 * Split a command line at blanks; double quotes keep blanks together and a backslash makes
	 * the next character plain (no variables or other shell syntax: the program is run as it is).
	 */
	static List<String> splitCommandLine(String line) {
		List<String> ret = new ArrayList<String>();
		StringBuilder b = new StringBuilder();
		boolean inWord = false;
		boolean quoted = false;
		for (int i = 0; i < line.length(); i++) {
			char c = line.charAt(i);
			if( c == '\\' && i+1 < line.length() ) {
				b.append(line.charAt(++i));
				inWord = true;
			} else if( c == '"' ) {
				quoted = !quoted;
				inWord = true;
			} else if( Character.isWhitespace(c) && !quoted ) {
				if( inWord ) {
					ret.add(b.toString());
					b.setLength(0);
					inWord = false;
				}
			} else {
				b.append(c);
				inWord = true;
			}
		}
		if( quoted ) {
			throw new IllegalStateException(PROPERTY_PREFIX+"."+PROPERTY_SHELL_COMMAND+": a double quote is not closed: "+line);
		}
		if( inWord ) {
			ret.add(b.toString());
		}
		return ret;
	}

	/**
	 * @return fsh's shell factory, or null if fsh isn't on the class path or this JVM can't run it
	 */
	private IShellFactory defaultShellFactory() {
		try {
			Class<?> c = Class.forName(DEFAULT_SHELL_FACTORY);
			return (IShellFactory) c.getDeclaredConstructor().newInstance();
		} catch (ClassNotFoundException e) {
			return null;
		} catch (Exception | LinkageError e) {
			// e.g. an fsh built for a newer Java than this one
			logInfo("fsh is on the class path but can't be used as the shell: "+e);
			return null;
		}
	}

	/**
	 * @param factory runs "shell" requests; null to look at the {@value #PROPERTY_SHELL_FACTORY}
	 * property (and the fsh default) again on the next use
	 */
	public void setShellFactory(IShellFactory factory) {
		this.shellFactory = factory;
		this.shellFactoryConfigured = factory != null;
	}

	/**
	 * Run the server; when it stops (every connection closed), close the subsystems that hold
	 * something for the server's life, such as SFTP's store claims.
	 */
	@Override
	public void run() {
		try {
			super.run();
		} finally {
			for (ISubsystemFactory f : subsystems.values()) {
				if( f instanceof AutoCloseable ) {
					try {
						((AutoCloseable) f).close();
					} catch (Exception e) {
						logError("Can't close subsystem "+f.getName(), e);
					}
				}
			}
		}
	}

	public void addSubsystem(ISubsystemFactory factory) {
		subsystems.put(factory.getName(), factory);
	}

	public void removeSubsystem(String name) {
		subsystems.remove(name);
	}

	public ISubsystemFactory getSubsystem(String name) {
		return subsystems.get(name);
	}

	// ------------------------------------------------------------------ settings

	public SshAlgorithms getAlgorithms() {
		return algorithms;
	}

	public void setAlgorithms(SshAlgorithms algorithms) {
		this.algorithms = algorithms;
	}

	public String getVersion() {
		return version;
	}

	public void setVersion(String version) {
		this.version = version;
	}

	public SecureRandom getRandom() {
		return random;
	}

	/**
	 * @return false: SSH encrypts itself, so the port never speaks TLS (the inherited "secure"
	 * property, meant for TLS servers, is ignored)
	 */
	@Override
	public boolean isSecure() {
		return false;
	}

	/**
	 * @throws IllegalArgumentException for true: an SSH server can't speak TLS
	 */
	@Override
	public synchronized void setSecure(boolean secure) {
		if( secure ) {
			throw new IllegalArgumentException("SSH encrypts itself: an SSH server can't use TLS");
		}
		super.setSecure(false);
	}

	public IHostKeyProvider getHostKeyProvider() {
		return hostKeyProvider;
	}

	public void setHostKeyProvider(IHostKeyProvider provider) {
		this.hostKeyProvider = provider;
		this.hostKeys = Collections.emptyList();
		this.hostCertificates = Collections.emptyList();
	}

	/**
	 * @return the host keys in use (empty until the server starts)
	 */
	public List<KeyPair> getHostKeys() {
		return hostKeys;
	}

	public us.bringardner.parley.ssh.keys.KeyRevocationList getRevokedKeys() {
		return revokedKeys;
	}

	/**
	 * @param revoked keys and certificates that can't log in (OpenSSH's RevokedKeys), or null;
	 * also set with the {@value #PROPERTY_REVOKED_KEYS} property
	 */
	public void setRevokedKeys(us.bringardner.parley.ssh.keys.KeyRevocationList revoked) {
		this.revokedKeys = revoked;
	}

	/**
	 * @return the host certificates in use (empty until the server starts)
	 */
	public List<SshCertificate> getHostCertificates() {
		return hostCertificates;
	}

	public String getBanner() {
		return banner;
	}

	/**
	 * @param banner text shown to users before they log in (e.g. a legal notice), null for none
	 */
	public void setBanner(String banner) {
		this.banner = banner;
	}

	// The login limits are the framework's (maxLoginAttempts, loginFailureDelay and
	// loginTimeLimit, set like any server setting), with OpenSSH's defaults

	@Override
	protected int getDefaultMaxLoginAttempts() {
		return DEFAULT_MAX_AUTH_TRIES;
	}

	@Override
	protected int getDefaultLoginFailureDelay() {
		return DEFAULT_AUTH_FAILURE_DELAY;
	}

	@Override
	protected int getDefaultLoginTimeLimit() {
		return DEFAULT_LOGIN_GRACE_TIME;
	}

	public boolean isSecurityKeyTouchRequired() {
		return securityKeyTouchRequired;
	}

	/**
	 * @param required true to require that users touch their security key even when the key
	 * or certificate says no-touch-required (OpenSSH's PubkeyAuthOptions touch-required);
	 * without it touch is required unless the key says otherwise
	 */
	public void setSecurityKeyTouchRequired(boolean required) {
		this.securityKeyTouchRequired = required;
	}

	public boolean isSecurityKeyVerifyRequired() {
		return securityKeyVerifyRequired;
	}

	/**
	 * @param required true to require user verification (PIN, biometrics) for every security
	 * key login (OpenSSH's PubkeyAuthOptions verify-required)
	 */
	public void setSecurityKeyVerifyRequired(boolean required) {
		this.securityKeyVerifyRequired = required;
	}

	public boolean isAgentForwardingAllowed() {
		return agentForwarding;
	}

	/**
	 * @param allowed true (default, as OpenSSH's AllowAgentForwarding) to let clients forward
	 * their agent (ssh -A); a key with no-agent-forwarding, or a certificate without
	 * permit-agent-forwarding, still can't
	 */
	public void setAgentForwardingAllowed(boolean allowed) {
		this.agentForwarding = allowed;
	}

	public IForwardingFilter getForwardingFilter() {
		return forwardingFilter;
	}

	/**
	 * @param filter which port forwarding users may do; null (default) refuses all of it
	 */
	public void setForwardingFilter(IForwardingFilter filter) {
		this.forwardingFilter = filter;
	}

	public int getMaxChannelsPerSession() {
		return maxChannelsPerSession;
	}

	/**
	 * @param n channels one connection may have open at once (OpenSSH: 10)
	 */
	public void setMaxChannelsPerSession(int n) {
		this.maxChannelsPerSession = n;
	}

	/**
	 * @return the pool that runs logins, commands and subsystems
	 */
	public ExecutorService getExecutor() {
		return executor;
	}

	/**
	 * @return for timers (login time limit, failure delay)
	 */
	public ScheduledExecutorService getScheduler() {
		return scheduler;
	}
}
