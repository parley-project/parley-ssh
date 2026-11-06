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
package us.bringardner.parley.ssh;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import us.bringardner.parley.files.FileSource;
import us.bringardner.parley.files.FileSourceFactory;

/**
 * The files SSH reads and writes (keys, certificates, known_hosts, authorized_keys,
 * config files) as {@link FileSource}s.
 * <p>
 * Paths that SSH itself works out (~/.ssh, a host key folder named in a setting) are on
 * the local file system: {@link #local(String)} always uses the local factory, never
 * {@link FileSourceFactory#getDefaultFactory()}, which an application may point somewhere else.
 * A FileSource handed in by the caller may come from any factory.
 */
public final class SshFiles {

	private SshFiles() {
	}

	/**
	 * @param path a path on the local file system (relative to the current directory if not absolute)
	 */
	public static FileSource local(String path) throws IOException {
		return FileSourceFactory.fileProxyFactory.createFileSource(path);
	}

	/**
	 * @return the user's ~/.ssh folder (it need not exist)
	 */
	public static FileSource userSshDir() throws IOException {
		return local(System.getProperty("user.home")).getChild(".ssh");
	}

	/**
	 * @return the file with this suffix added to its name, in the same folder and from the same
	 *  factory: id_ed25519 and ".pub" give id_ed25519.pub
	 */
	public static FileSource withSuffix(FileSource file, String suffix) throws IOException {
		return file.getFileSourceFactory().createFileSource(file.getAbsolutePath()+suffix);
	}

	public static byte[] readAllBytes(FileSource file) throws IOException {
		try (InputStream in = file.getInputStream()) {
			ByteArrayOutputStream out = new ByteArrayOutputStream();
			byte[] buf = new byte[8192];
			int got;
			while ((got = in.read(buf)) >= 0) {
				out.write(buf, 0, got);
			}
			return out.toByteArray();
		}
	}

	/**
	 * @return the file's UTF-8 lines, as Files.readAllLines splits them (\n, \r\n or \r)
	 */
	public static List<String> readAllLines(FileSource file) throws IOException {
		String text = new String(readAllBytes(file), StandardCharsets.UTF_8);
		List<String> ret = new ArrayList<String>(Arrays.asList(text.split("\r\n|\n|\r", -1)));
		// A final line break ends the last line; it doesn't start an empty one
		if( !ret.isEmpty() && ret.get(ret.size()-1).isEmpty() ) {
			ret.remove(ret.size()-1);
		}
		return ret;
	}

	/**
	 * Replace the file's contents.
	 */
	public static void write(FileSource file, byte[] data) throws IOException {
		try (java.io.OutputStream out = file.getOutputStream(false)) {
			out.write(data);
		}
	}

	/**
	 * Add to the end of the file, making it if it doesn't exist.
	 */
	public static void append(FileSource file, byte[] data) throws IOException {
		try (java.io.OutputStream out = file.getOutputStream(true)) {
			out.write(data);
		}
	}

	/**
	 * Make the file's folder (and its parents) if it doesn't exist.
	 */
	public static void makeParentFolder(FileSource file) throws IOException {
		FileSource dir = file.getParentFile();
		if( dir != null && !dir.exists() && !dir.mkdirs() && !dir.isDirectory() ) {
			throw new IOException("Can't create "+dir);
		}
	}
}
