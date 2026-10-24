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
import java.util.regex.Pattern;

import us.bringardner.parley.files.fileproxy.FileProxyFactory;
import us.bringardner.parley.net.server.IPrincipal;
import us.bringardner.parley.ssh.sftp.server.SftpSubsystemFactory;

/**
 * SFTP for {@link ServiceSetup}: a class of its own, so parley-files (an optional dependency) is
 * only loaded when it is on the class path.
 *
 * @author Tony Bringardner
 */
final class SftpSetup {

	/** The access control list's parameter for a user's root folder: the same one FTP uses */
	static final String PARAMETER_USER_ROOT = "userRoot";
	/** User names that can't climb out of the homes folder */
	private static final Pattern SAFE_USER = Pattern.compile("[A-Za-z0-9._][A-Za-z0-9._-]*");

	private SftpSetup() {
	}

	/**
	 * Each user's root: the principal's userRoot parameter, else homes/USER; a user with neither
	 * folder gets no SFTP
	 */
	static void add(SshServer server, File homes) {
		server.addSubsystem(new SftpSubsystemFactory(env -> {
			File dir = rootOf(env.getPrincipal(), env.getUser(), homes);
			if( dir == null || !dir.isDirectory() ) {
				server.logInfo("No SFTP for "+env.getUser()+": no folder "+dir);
				return null;
			}
			return new FileProxyFactory().createFileSource(dir.getCanonicalPath());
		}));
	}

	/** null for a user name that could leave the homes folder */
	static File rootOf(IPrincipal principal, String user, File homes) {
		Object root = principal == null ? null : principal.getParameter(PARAMETER_USER_ROOT);
		if( root != null && !root.toString().trim().isEmpty() ) {
			return new File(root.toString().trim());
		}
		if( user == null || !SAFE_USER.matcher(user).matches() || user.contains("..") ) {
			return null;
		}
		return new File(homes, user);
	}
}
