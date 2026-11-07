/**
 * <PRE>
 *
 * Copyright 2026 <A href="http://bringardner.us/tony">Tony Bringardner</A>
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
 */
package us.bringardner.parley.ssh.server;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Locale;
import java.util.Set;

import us.bringardner.parley.iam.AuthenticationResult;
import us.bringardner.parley.iam.AuthorizationResult;
import us.bringardner.parley.iam.Credential;
import us.bringardner.parley.iam.EntityId;
import us.bringardner.parley.iam.ParleyPermission;
import us.bringardner.parley.iam.ParleyPrincipal;
import us.bringardner.parley.iam.ProtectedResource;
import us.bringardner.parley.iam.Requester;
import us.bringardner.parley.iam.StoredCredential;
import us.bringardner.parley.iam.StoredCredentialType;
import us.bringardner.parley.iam.UserRegistry;
import us.bringardner.parley.iam.UserRegistryUnavailableException;
import us.bringardner.parley.iam.credential.PasswordCredential;
import us.bringardner.parley.iam.principal.BasicParleyPrincipal;

/**
 * The tests' user registry: the users named (or any user name when none are named), all with
 * one password, every permission except the ones denied. With its no-argument constructor
 * (as a server makes it from {@code authenticationProvider}): any user, password
 * {@value #PASSWORD}.
 */
public class TestUsers implements UserRegistry {

	public static final String PASSWORD = "secret";

	private final String password;
	private final Set<String> names;
	private final Set<String> denied = new HashSet<String>();
	private boolean passwords = true;

	/** Any user name, password {@value #PASSWORD} */
	public TestUsers() {
		this(PASSWORD);
	}

	/**
	 * @param password every user's password
	 * @param names the users; none: any user name
	 */
	public TestUsers(String password, String... names) {
		this.password = password;
		this.names = names.length == 0 ? null : new HashSet<String>(Arrays.asList(names));
	}

	/** Any user name, and no password logins: for servers whose users log in with keys */
	public static TestUsers keysOnly() {
		TestUsers ret = new TestUsers();
		ret.passwords = false;
		return ret;
	}

	/** @return this, without these permissions for anyone */
	public TestUsers deny(String... permissions) {
		for (String p : permissions) {
			denied.add(p.toLowerCase(Locale.ROOT));
		}
		return this;
	}

	private boolean known(String name) {
		return name != null && !name.isEmpty() && (names == null || names.contains(name));
	}

	private static ParleyPrincipal principal(String name) {
		return BasicParleyPrincipal.user(EntityId.of("user:"+name), name);
	}

	@Override
	public boolean supports(Class<? extends Credential> kind, StoredCredentialType stored) {
		return passwords && kind == PasswordCredential.class && stored == null;
	}

	@Override
	public AuthenticationResult authenticate(Credential credential) {
		if( !(credential instanceof PasswordCredential) || !passwords ) {
			return AuthenticationResult.unsupported("passwords only");
		}
		char[] pw = ((PasswordCredential) credential).getPassword();
		try {
			if( !known(credential.getUser()) || !password.equals(new String(pw)) ) {
				return AuthenticationResult.refused("wrong user or password");
			}
		} finally {
			Arrays.fill(pw, '\0');
		}
		return AuthenticationResult.authenticated(principal(credential.getUser()), "password");
	}

	@Override
	public StoredCredential findStoredCredential(String user, StoredCredentialType type) throws UserRegistryUnavailableException {
		return null;
	}

	@Override
	public ParleyPrincipal findPrincipal(String name) throws UserRegistryUnavailableException {
		return known(name) ? principal(name) : null;
	}

	@Override
	public ParleyPrincipal findPrincipal(EntityId id) throws UserRegistryUnavailableException {
		String v = id == null ? null : id.getValue();
		return v != null && v.startsWith("user:") ? findPrincipal(v.substring(5)) : null;
	}

	@Override
	public AuthorizationResult checkPermission(Requester requester, ParleyPermission needed, ProtectedResource resource) {
		if( requester.getPrincipal() == null ) {
			return AuthorizationResult.denied("nobody logged in");
		}
		if( denied.contains(needed.getName().toLowerCase(Locale.ROOT)) ) {
			return AuthorizationResult.denied(needed.getName()+" is denied");
		}
		return AuthorizationResult.allowed("tests may do anything");
	}

	/** @return the names this registry was made with (empty: any) */
	public Set<String> getNames() {
		return names == null ? Collections.<String>emptySet() : Collections.unmodifiableSet(names);
	}
}
