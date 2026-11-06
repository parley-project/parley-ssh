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

import us.bringardner.parley.iam.AuthenticationResult;
import us.bringardner.parley.iam.ParleyPrincipal;
import us.bringardner.parley.ssh.SshBuffer;

/**
 * A server side user authentication method (RFC 4252), e.g. "password" or "publickey".
 * The server offers the methods it has, in order; a request for one goes to it.
 * <p>
 * A method logs the session in only through the session's own door,
 * {@link IServerAuthContext#authenticate}: the server's user registry says who the user is,
 * and the session counts (and slows down) refused logins. A success the session didn't log in
 * is treated as a failure.
 * <p>
 * Methods are shared by all sessions: keep per-session state in the context.
 *
 * @author Tony Bringardner
 * @see PasswordAuthMethod
 * @see PublicKeyAuthMethod
 * @see KeyboardInteractiveAuthMethod
 */
public interface IServerAuthMethod {

	/**
	 * The outcome of a request.
	 */
	final class Result {
		/** Not authenticated */
		public static final Result FAILURE = new Result(null, false, null);
		/** The method sent its own message (PK_OK, INFO_REQUEST) and waits for the client */
		public static final Result PENDING = new Result(null, true, null);

		private final ParleyPrincipal principal;
		private final boolean pending;
		private final String unavailable;

		private Result(ParleyPrincipal principal, boolean pending, String unavailable) {
			this.principal = principal;
			this.pending = pending;
			this.unavailable = unavailable;
		}

		/**
		 * @param principal the authenticated user, as the session's authenticate gave it
		 */
		public static Result success(ParleyPrincipal principal) {
			if( principal == null ) {
				throw new IllegalArgumentException("principal");
			}
			return new Result(principal, false, null);
		}

		/**
		 * The user registry can't answer now (a database outage, say): not a wrong password.
		 * The session tells the client to try again later.
		 *
		 * @param reason why, for the log
		 * @since 2.0.0
		 */
		public static Result unavailable(String reason) {
			return new Result(null, false, reason == null ? "unavailable" : reason);
		}

		/**
		 * @param result what the session's authenticate (or the server's probe) answered
		 * @return success for AUTHENTICATED, unavailable for UNAVAILABLE, else FAILURE
		 * @since 2.0.0
		 */
		public static Result of(AuthenticationResult result) {
			switch (result.getStatus()) {
				case AUTHENTICATED:
					return success(result.getPrincipal());
				case UNAVAILABLE:
					return unavailable(result.getReason());
				default:
					return FAILURE;
			}
		}

		public boolean isSuccess() {
			return principal != null;
		}

		public boolean isPending() {
			return pending;
		}

		/**
		 * @return true when the user registry couldn't answer
		 * @since 2.0.0
		 */
		public boolean isUnavailable() {
			return unavailable != null;
		}

		/**
		 * @return why the user registry couldn't answer, or null
		 * @since 2.0.0
		 */
		public String getReason() {
			return unavailable;
		}

		public ParleyPrincipal getPrincipal() {
			return principal;
		}
	}

	String getName();

	/**
	 * An SSH_MSG_USERAUTH_REQUEST for this method.
	 *
	 * @param user the user name
	 * @param data the method specific part
	 */
	Result request(IServerAuthContext context, String user, SshBuffer data) throws IOException;

	/**
	 * A method specific message from the client (e.g. 61, keyboard-interactive's INFO_RESPONSE),
	 * after this method returned PENDING.
	 */
	default Result handle(IServerAuthContext context, int msg, SshBuffer data) throws IOException {
		throw new us.bringardner.parley.ssh.SshException("Unexpected message "+msg+" for "+getName());
	}
}
