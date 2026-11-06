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
import java.net.SocketAddress;
import java.util.Map;

import us.bringardner.parley.iam.AuthenticationResult;
import us.bringardner.parley.iam.Credential;
import us.bringardner.parley.iam.Requester;
import us.bringardner.parley.ssh.SshBuffer;

/**
 * What a server authentication method can use for one session.
 *
 * @author Tony Bringardner
 */
public interface IServerAuthContext {

	SshServer getServer();

	/**
	 * @return H of the first key exchange (what publickey signatures cover)
	 */
	byte[] getSessionId();

	SocketAddress getRemoteAddress();

	/**
	 * @return the service the client asked for ("ssh-connection")
	 */
	String getService();

	void send(SshBuffer message) throws IOException;

	/**
	 * @return state a method keeps between messages of this session (e.g. keyboard-interactive's user)
	 */
	Map<String, Object> getAttributes();

	/**
	 * @return who is asking: the session's requester, for the credentials a method makes
	 * @since 2.0.0
	 */
	Requester getRequester();

	/**
	 * Log the session in with this credential: the session's authenticate, the one door
	 * (the server's user registry checks it; a refusal is counted and its reply delayed).
	 *
	 * @return the registry's answer; AUTHENTICATED logs the session in
	 * @since 2.0.0
	 */
	AuthenticationResult authenticate(Credential credential);

	/**
	 * Would this credential do? The server's probe: nothing is logged in, counted or recorded
	 * (publickey's query without a signature).
	 *
	 * @since 2.0.0
	 */
	AuthenticationResult probe(Credential credential);
}
