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
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.List;

import us.bringardner.parley.ssh.SshBuffer;
import us.bringardner.parley.ssh.SshConstants;
import us.bringardner.parley.ssh.algorithms.SshCertificate;
import us.bringardner.parley.ssh.algorithms.SshPublicKeys;
import us.bringardner.parley.ssh.keys.SshKeyLoader;

/**
 * {@link SshMain}'s login methods that ask the user, only when the server gets that far: a
 * password (asked again after a wrong one, as OpenSSH's NumberOfPasswordPrompts), the
 * prompts of keyboard-interactive, and the passphrase of a key file (asked once the server said
 * it would accept the key, when its .pub file is there to ask with).
 *
 * @author Tony Bringardner
 */
final class PromptedAuth {

	private PromptedAuth() {
	}

	/** "password", asking for it each time */
	static final class Password implements IClientAuthMethod {

		private final CliTerminal terminal;
		private final String prompt;
		private int left;
		private PasswordAuth current;

		/**
		 * @param prompt e.g. "tony@example.com's password: "
		 * @param attempts how many passwords to try
		 */
		Password(CliTerminal terminal, String prompt, int attempts) {
			this.terminal = terminal;
			this.prompt = prompt;
			this.left = attempts;
		}

		@Override
		public String getName() {
			return "password";
		}

		@Override
		public boolean start(IClientAuthContext context) throws IOException {
			if( left <= 0 ) {
				return false;
			}
			left--;
			char[] pw = terminal.prompt(prompt, false);
			if( pw == null ) {
				left = 0;
				terminal.err().println("Can't read a password (no terminal, no SSH_ASKPASS, and stdin ended)");
				return false;
			}
			try {
				current = new PasswordAuth(pw);
			} finally {
				Arrays.fill(pw, '\0');
			}
			return current.start(context);
		}

		@Override
		public boolean handle(int msg, SshBuffer message, IClientAuthContext context) throws IOException {
			return current != null && current.handle(msg, message, context);
		}

		@Override
		public boolean retry(IClientAuthContext context) throws IOException {
			if( left <= 0 ) {
				return false;
			}
			terminal.err().println("Permission denied, please try again.");
			return start(context);
		}
	}

	/** keyboard-interactive's prompts asked on the terminal */
	static KeyboardInteractiveAuth keyboardInteractive(CliTerminal terminal) {
		return new KeyboardInteractiveAuth((name, instruction, prompts, echo) -> {
			PrintStream err = terminal.err();
			if( name != null && !name.isEmpty() ) {
				err.println(name);
			}
			if( instruction != null && !instruction.isEmpty() ) {
				err.println(instruction);
			}
			String[] answers = new String[prompts.length];
			for (int i = 0; i < prompts.length; i++) {
				char[] a = terminal.prompt(prompts[i], echo[i]);
				if( a == null ) {
					return null;
				}
				answers[i] = new String(a);
				Arrays.fill(a, '\0');
			}
			return answers;
		});
	}

	/**
	 * "publickey" with a passphrase protected key file. With the public key known (the .pub
	 * file), the server is asked first whether it would accept the key, so the passphrase is only
	 * asked for a key that can be used; without it, the passphrase is asked right away.
	 */
	static final class EncryptedKey implements IClientAuthMethod {

		private static final int PASSPHRASE_ATTEMPTS = 3;

		private final CliTerminal terminal;
		private final File file;
		private final String text;
		private final PublicKey publicKey;
		private final List<File> certificates;
		/** while asking the server about publicKey */
		private boolean probing;
		private PublicKeyAuth delegate;

		/**
		 * @param text the key file's contents
		 * @param publicKey from the .pub file, null if there is none
		 * @param certificates certificate files for the key (those that are there)
		 */
		EncryptedKey(CliTerminal terminal, File file, String text, PublicKey publicKey, List<File> certificates) {
			this.terminal = terminal;
			this.file = file;
			this.text = text;
			this.publicKey = publicKey;
			this.certificates = certificates;
		}

		@Override
		public String getName() {
			return "publickey";
		}

		@Override
		public boolean start(IClientAuthContext context) throws IOException {
			if( publicKey != null && certificates.isEmpty() ) {
				// As PublicKeyAuth will sign: null if the server can't take this kind of key
				String alg = PublicKeyAuth.algorithm(publicKey, context);
				if( alg == null ) {
					return false;
				}
				probing = true;
				context.send(context.newRequest(getName()).putBoolean(false).putString(alg).putString(SshPublicKeys.encode(publicKey)));
				return true;
			}
			return unlockAndStart(context);
		}

		private boolean unlockAndStart(IClientAuthContext context) throws IOException {
			probing = false;
			KeyPair key = unlock();
			if( key == null ) {
				return false;
			}
			delegate = new PublicKeyAuth(key);
			for (File c : certificates) {
				try {
					delegate.addCertificate(key, SshCertificate.load(c));
				} catch (IOException | IllegalArgumentException e) {
					// not this key's, or unreadable: the plain key is still offered
				}
			}
			return delegate.start(context);
		}

		private KeyPair unlock() {
			for (int i = 0; i < PASSPHRASE_ATTEMPTS; i++) {
				char[] pp = terminal.prompt("Enter passphrase for key '"+file+"': ", false);
				if( pp == null || pp.length == 0 ) {
					return null;
				}
				try {
					return SshKeyLoader.parse(text, pp);
				} catch (IOException e) {
					String m = String.valueOf(e.getMessage());
					if( !m.toLowerCase(java.util.Locale.ROOT).contains("wrong passphrase") ) {
						// Not the passphrase: asking again won't help
						terminal.err().println("Load key \""+file+"\": "+m);
						return null;
					}
				} finally {
					Arrays.fill(pp, '\0');
				}
			}
			return null;
		}

		@Override
		public boolean handle(int msg, SshBuffer message, IClientAuthContext context) throws IOException {
			if( probing && msg == SshConstants.SSH_MSG_USERAUTH_60 ) {
				// PK_OK: the server would take this key
				if( !unlockAndStart(context) ) {
					context.methodFailed("Key "+file+" not used");
				}
				return true;
			}
			return delegate != null && delegate.handle(msg, message, context);
		}

		@Override
		public boolean retry(IClientAuthContext context) throws IOException {
			if( probing ) {
				// The server doesn't know the key
				probing = false;
				return false;
			}
			return delegate != null && delegate.retry(context);
		}
	}
}
