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

import java.io.DataInputStream;
import java.io.EOFException;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.AccessDeniedException;
import java.nio.file.NoSuchFileException;
import java.nio.file.attribute.GroupPrincipal;
import java.nio.file.attribute.UserPrincipal;
import java.text.SimpleDateFormat;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.Deque;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import us.bringardner.parley.files.FileSource;
import us.bringardner.parley.files.IRandomAccessStream;
import us.bringardner.parley.net.lock.LockDomain;
import us.bringardner.parley.net.lock.Locks;
import us.bringardner.parley.net.lock.NamedLock;
import us.bringardner.parley.net.lock.StoreClaim;
import us.bringardner.parley.net.lock.StoreLocks;
import us.bringardner.parley.ssh.SshBuffer;
import us.bringardner.parley.ssh.server.AbstractCommand;
import us.bringardner.parley.ssh.server.CommandEnvironment;
import us.bringardner.parley.ssh.sftp.SftpAttrs;
import us.bringardner.parley.ssh.sftp.SftpConstants;

/**
 * One SFTP session on a {@link FileSource} root: version 3 (draft-ietf-secsh-filexfer-02 as
 * OpenSSH implements it, with OpenSSH's posix-rename, hardlink and fsync extensions) and
 * versions 4 to 6 (drafts 04, 05 and 13: typed attributes with owner names and nanosecond
 * times, version 5's open dispositions and rename flags, version 6's LINK and status codes).
 * The client's version is used, up to 6; a version 3 client can move up with the "versions"
 * and "version-select" extensions. Byte range locks (version 6 BLOCK) are not supported.
 * <p>
 * The client sees the root as "/" (also its login directory). Every path is checked with
 * {@link FileSource#isChildOfMine(FileSource)}, which resolves symbolic links, so nothing
 * outside the root can be read, written or listed. Operations on a link itself (lstat,
 * remove, rename, readlink) check its directory instead, so a link that points outside can
 * still be seen and removed but not followed. Error messages don't show real paths.
 * <p>
 * Requests are answered in order on one thread, which is what SFTP clients expect.
 * <p>
 * Writers keep out of each other, here and on other servers sharing the store (parley-net's
 * {@link StoreLocks}; how many servers share it is {@value #SHARED_STORE_PROPERTY}: {@code off},
 * the default, {@code host} or {@code cluster}): a file open for writing holds its lock until it
 * is closed, and while another session holds it, opening it for writing, removing it, renaming it
 * or changing its size is refused at once ({@code SSH_FX_LOCK_CONFLICT}, or {@code SSH_FX_FAILURE}
 * before version 5). One session may open a file for writing more than once. Reading takes no
 * lock: a reader sees the file as it is being written. The store's lock directory
 * ({@value Locks#DIRECTORY}) can't be seen or reached.
 *
 * @author Tony Bringardner
 */
public class SftpServer extends AbstractCommand {

	/** Largest request accepted (a 256 KB write and its header fit) */
	private static final int MAX_PACKET = 1024*1024;
	/** Most bytes one READ returns (OpenSSH's limit) */
	private static final int MAX_READ = 255*1024;
	private static final int MAX_HANDLES = 256;
	private static final int DIR_BATCH = 100;
	private static final int S_IFDIR = 0040000;
	private static final int S_IFREG = 0100000;
	private static final int S_IFLNK = 0120000;

	/** A status to send, with the message the client sees */
	private static final class Status extends IOException {
		private static final long serialVersionUID = 1L;
		final int code;

		Status(int code, String message) {
			super(message);
			this.code = code;
		}
	}

	/** System property: how many servers share the store (off, host, cluster; default off). */
	public static final String SHARED_STORE_PROPERTY = "parley.ssh.sftp.sharedStore";
	/** System property: this server's id among those that share the store (default: host and process). */
	public static final String SERVER_ID_PROPERTY = "parley.ssh.sftp.serverId";

	/** A file's lock, with the domain it is in (kept open while it is held). */
	private static final class FileLock {
		final LockDomain domain;
		final NamedLock lock;

		FileLock(LockDomain domain, NamedLock lock) {
			this.domain = domain;
			this.lock = lock;
		}

		void close() {
			try {
				lock.close();
			} finally {
				StoreLocks.get().release(domain);
			}
		}
	}

	private static final class FileHandle {
		final FileSource file;
		final IRandomAccessStream raf;
		final boolean writable;
		final boolean append;
		/** The file's lock while it is open for writing, or null */
		final FileLock lock;

		FileHandle(FileSource file, IRandomAccessStream raf, boolean writable, boolean append, FileLock lock) {
			this.file = file;
			this.raf = raf;
			this.writable = writable;
			this.append = append;
			this.lock = lock;
		}

		void close() throws IOException {
			try {
				raf.close();
			} finally {
				if( lock != null ) {
					lock.close();
				}
			}
		}
	}

	private static final class DirHandle {
		final FileSource dir;
		final Deque<FileSource> entries;
		boolean dotsSent;

		DirHandle(FileSource dir, Deque<FileSource> entries) {
			this.dir = dir;
			this.entries = entries;
		}
	}

	private final FileSource root;
	private final boolean readOnly;
	private final Map<String, Object> handles = new HashMap<String, Object>();
	private int nextHandle;
	private OutputStream out;
	private int version = SftpConstants.SFTP_VERSION;
	// version-select is only allowed as the first request
	private boolean requested;

	public SftpServer(FileSource root, boolean readOnly) {
		this.root = root;
		this.readOnly = readOnly;
	}

	@Override
	protected int run(CommandEnvironment env, InputStream in, OutputStream out, OutputStream err) throws Exception {
		this.out = out;
		DataInputStream din = new DataInputStream(in);
		// the store's locks, with the servers here and those sharing it; refused if another server
		// has it alone
		LockDomain domain;
		StoreClaim claim;
		try {
			domain = StoreLocks.get().acquire(root, StoreLocks.sharing(SHARED_STORE_PROPERTY));
		} catch (IOException e) {
			logError("SFTP: can't set up the locks of "+root.getAbsolutePath(), e);
			return 1;
		}
		try {
			claim = domain.claimStore(StoreLocks.serverId(SERVER_ID_PROPERTY, "sftp", 0));
		} catch (IOException e) {
			StoreLocks.get().release(domain);
			logError("SFTP: "+e.getMessage(), e);
			return 1;
		}
		try {
			while( !isDestroyed() ) {
				int len;
				try {
					len = din.readInt();
				} catch (EOFException e) {
					return 0;
				}
				if( len < 1 || len > MAX_PACKET ) {
					logDebug("SFTP packet of "+len+" bytes, closing");
					return 1;
				}
				byte[] packet = new byte[len];
				din.readFully(packet);
				process(new SshBuffer(packet));
			}
			return 0;
		} finally {
			try {
				closeAll();
			} finally {
				claim.close();
				StoreLocks.get().release(domain);
			}
		}
	}

	private void closeAll() {
		for (Object h : handles.values()) {
			if( h instanceof FileHandle ) {
				try {
					((FileHandle) h).close();
				} catch (IOException | RuntimeException e) {
					// closing anyway
				}
			}
		}
		handles.clear();
	}

	/**
	 * The file's lock, for writing it, removing it or renaming it: taken at once or refused. A
	 * session may take one it holds again (a second handle).
	 * @return the lock, or null for a file outside every registered store (none to take)
	 * @throws Status if another session or server holds it
	 */
	private FileLock lock(FileSource f) throws IOException {
		LockDomain d = StoreLocks.get().acquireFor(f);
		if( d == null ) {
			return null;
		}
		NamedLock l;
		try {
			l = d.request(StoreLocks.fileLockName(d, f)).exclusive().tryAcquire();
		} catch (IOException | RuntimeException e) {
			StoreLocks.get().release(d);
			throw e;
		}
		if( l == null ) {
			StoreLocks.get().release(d);
			throw new Status(SftpConstants.SSH_FX_LOCK_CONFLICT, "The file is being written by another session");
		}
		return new FileLock(d, l);
	}

	private static void closeQuietly(FileLock l) {
		if( l != null ) {
			l.close();
		}
	}

	// ------------------------------------------------------------------ dispatch

	private void process(SshBuffer p) throws IOException {
		int type = p.getByte();
		if( type == SftpConstants.SSH_FXP_INIT ) {
			long client = p.getUInt();
			version = (int) Math.max(SftpConstants.SFTP_VERSION, Math.min(client, SftpConstants.SFTP_MAX_VERSION));
			SshBuffer b = new SshBuffer().putByte(SftpConstants.SSH_FXP_VERSION).putInt(version);
			b.putString(SftpConstants.EXT_POSIX_RENAME).putString("1");
			b.putString(SftpConstants.EXT_HARDLINK).putString("1");
			b.putString(SftpConstants.EXT_FSYNC).putString("1");
			if( version == SftpConstants.SFTP_VERSION ) {
				// A client that started with 3 may select a later one (draft 13, 5.5)
				b.putString(SftpConstants.EXT_VERSIONS).putString("3,4,5,6");
			}
			send(b);
			return;
		}
		int id = p.getInt();
		boolean first = !requested;
		requested = true;
		try {
			if( type == SftpConstants.SSH_FXP_EXTENDED && first ) {
				int at = p.readPosition();
				if( SftpConstants.EXT_VERSION_SELECT.equals(p.getStringUtf8()) ) {
					selectVersion(id, p.getStringUtf8());
					return;
				}
				p.readPosition(at);
			}
			switch (type) {
			case SftpConstants.SSH_FXP_OPEN: open(id, p); break;
			case SftpConstants.SSH_FXP_CLOSE: close(id, p); break;
			case SftpConstants.SSH_FXP_READ: read(id, p); break;
			case SftpConstants.SSH_FXP_WRITE: write(id, p); break;
			case SftpConstants.SSH_FXP_STAT: attrs(id, attributes(followed(p.getStringUtf8()), true)); break;
			case SftpConstants.SSH_FXP_LSTAT: attrs(id, attributes(notFollowed(p.getStringUtf8()), false)); break;
			case SftpConstants.SSH_FXP_FSTAT: attrs(id, attributes(fileHandle(p.getString()).file, true)); break;
			case SftpConstants.SSH_FXP_SETSTAT: setStat(id, p); break;
			case SftpConstants.SSH_FXP_FSETSTAT: fsetStat(id, p); break;
			case SftpConstants.SSH_FXP_OPENDIR: openDir(id, p); break;
			case SftpConstants.SSH_FXP_READDIR: readDir(id, p); break;
			case SftpConstants.SSH_FXP_REMOVE: remove(id, p); break;
			case SftpConstants.SSH_FXP_MKDIR: mkdir(id, p); break;
			case SftpConstants.SSH_FXP_RMDIR: rmdir(id, p); break;
			case SftpConstants.SSH_FXP_REALPATH: realpath(id, p); break;
			case SftpConstants.SSH_FXP_RENAME: {
				String from = p.getStringUtf8();
				String to = p.getStringUtf8();
				int flags = version >= 5 ? (int) p.getUInt() : 0;
				rename(id, from, to, (flags & (SftpConstants.SSH_FXF_RENAME_OVERWRITE | SftpConstants.SSH_FXF_RENAME_ATOMIC)) != 0);
				break;
			}
			case SftpConstants.SSH_FXP_READLINK: readlink(id, p); break;
			case SftpConstants.SSH_FXP_SYMLINK:
				if( version >= 6 ) {
					status(id, SftpConstants.SSH_FX_OP_UNSUPPORTED, "Use LINK");
				} else if( version == 3 ) {
					// OpenSSH's order: target first
					String target = p.getStringUtf8();
					symlink(id, target, p.getStringUtf8());
				} else {
					String[] tl = targetAndLink(p.getStringUtf8(), p.getStringUtf8());
					symlink(id, tl[0], tl[1]);
				}
				break;
			case SftpConstants.SSH_FXP_LINK:
				if( version < 6 ) {
					status(id, SftpConstants.SSH_FX_OP_UNSUPPORTED, "Unsupported request "+type);
				} else {
					String[] tl = targetAndLink(p.getStringUtf8(), p.getStringUtf8());
					if( p.getBoolean() ) {
						symlink(id, tl[0], tl[1]);
					} else {
						hardlink(id, tl[0], tl[1]);
					}
				}
				break;
			case SftpConstants.SSH_FXP_EXTENDED: extended(id, p); break;
			default:
				status(id, SftpConstants.SSH_FX_OP_UNSUPPORTED, "Unsupported request "+type);
			}
		} catch (Status s) {
			status(id, s.code, s.getMessage());
		} catch (NoSuchFileException | FileNotFoundException e) {
			status(id, SftpConstants.SSH_FX_NO_SUCH_FILE, "No such file");
		} catch (AccessDeniedException | SecurityException e) {
			status(id, SftpConstants.SSH_FX_PERMISSION_DENIED, "Permission denied");
		} catch (us.bringardner.parley.ssh.SshException e) {
			status(id, SftpConstants.SSH_FX_BAD_MESSAGE, "Bad message");
		} catch (IOException | RuntimeException e) {
			// The message may hold real paths: logged, not sent
			logDebug("SFTP request "+type+" failed", e);
			status(id, SftpConstants.SSH_FX_FAILURE, "Failure");
		}
	}

	// ------------------------------------------------------------------ paths

	/**
	 * @return the path as the client sees it: absolute, "." and ".." resolved, never above "/"
	 */
	static String normalize(String path) {
		Deque<String> parts = new ArrayDeque<String>();
		for (String seg : path.replace('\\', '/').split("/")) {
			if( seg.isEmpty() || seg.equals(".") ) {
				continue;
			}
			if( seg.equals("..") ) {
				parts.pollLast();
			} else {
				parts.add(seg);
			}
		}
		return "/"+String.join("/", parts);
	}

	private FileSource resolve(String vpath) throws IOException {
		FileSource f = root;
		for (String seg : normalize(vpath).split("/")) {
			if( !seg.isEmpty() ) {
				f = f.getChild(seg);
			}
		}
		return f;
	}

	/**
	 * The path with links followed; it must be inside the root.
	 */
	private FileSource followed(String path) throws IOException {
		FileSource f = resolve(path);
		if( !root.isChildOfMine(f) || StoreLocks.get().isLockFile(f) ) {
			throw new Status(SftpConstants.SSH_FX_PERMISSION_DENIED, "Permission denied");
		}
		return f;
	}

	/**
	 * The path itself (a link is not followed); its directory must be inside the root.
	 */
	private FileSource notFollowed(String path) throws IOException {
		String n = normalize(path);
		if( n.equals("/") ) {
			return root;
		}
		int i = n.lastIndexOf('/');
		FileSource parent = followed(n.substring(0, Math.max(1, i)));
		FileSource f = parent.getChild(n.substring(i+1));
		if( StoreLocks.get().isLockFile(f) ) {
			throw new Status(SftpConstants.SSH_FX_PERMISSION_DENIED, "Permission denied");
		}
		return f;
	}

	private void writable() throws Status {
		if( readOnly ) {
			throw new Status(SftpConstants.SSH_FX_PERMISSION_DENIED, "Read-only");
		}
	}

	private static boolean isLink(FileSource f) {
		try {
			return f.getLinkedTo() != null;
		} catch (IOException | RuntimeException e) {
			return false;
		}
	}

	// ------------------------------------------------------------------ files

	private void open(int id, SshBuffer p) throws IOException {
		String path = p.getStringUtf8();
		int flags = (int) p.getUInt();
		if( version >= 5 ) {
			flags = pflags(flags, (int) p.getUInt());
		}
		SftpAttrs attrs = SftpAttrs.read(p, version);
		boolean write = (flags & (SftpConstants.SSH_FXF_WRITE | SftpConstants.SSH_FXF_APPEND)) != 0;
		boolean creat = (flags & SftpConstants.SSH_FXF_CREAT) != 0;
		if( write || creat || (flags & SftpConstants.SSH_FXF_TRUNC) != 0 ) {
			writable();
		}
		if( handles.size() >= MAX_HANDLES ) {
			throw new Status(SftpConstants.SSH_FX_FAILURE, "Too many open files");
		}
		FileSource f = followed(path);
		boolean exists = f.exists();
		if( exists && f.isDirectory() ) {
			throw new Status(SftpConstants.SSH_FX_FILE_IS_A_DIRECTORY, "Is a directory");
		}
		// a writer takes the file's lock before it creates or empties it, and keeps it until close
		FileLock lock = write || (flags & SftpConstants.SSH_FXF_TRUNC) != 0 ? lock(f) : null;
		try {
			openLocked(id, f, exists, flags, write, creat, attrs, lock);
		} catch (IOException | RuntimeException e) {
			closeQuietly(lock);
			throw e;
		}
	}

	private void openLocked(int id, FileSource f, boolean exists, int flags, boolean write, boolean creat, SftpAttrs attrs,
			FileLock lock) throws IOException {
		if( !exists ) {
			if( !creat ) {
				throw new Status(SftpConstants.SSH_FX_NO_SUCH_FILE, "No such file");
			}
			if( !f.createNewFile() && (flags & SftpConstants.SSH_FXF_EXCL) != 0 ) {
				throw new Status(SftpConstants.SSH_FX_FILE_ALREADY_EXISTS, "File exists");
			}
			if( attrs.hasPermissions() ) {
				setPermissions(f, attrs.getPermissions());
			}
		} else if( creat && (flags & SftpConstants.SSH_FXF_EXCL) != 0 ) {
			throw new Status(SftpConstants.SSH_FX_FILE_ALREADY_EXISTS, "File exists");
		}
		IRandomAccessStream raf = f.getRandomAccessStream(write ? "rw" : "r");
		try {
			if( write && (flags & SftpConstants.SSH_FXF_TRUNC) != 0 ) {
				raf.setLength(0);
			}
		} catch (IOException | RuntimeException e) {
			raf.close();
			throw e;
		}
		handle(id, new FileHandle(f, raf, write, (flags & SftpConstants.SSH_FXF_APPEND) != 0, lock));
	}

	/**
	 * Version 5+ desired access and flags as version 3 flags
	 */
	private static int pflags(int access, int flags) {
		int ret = 0;
		if( (access & (SftpConstants.ACE4_READ_DATA | SftpConstants.ACE4_READ_ATTRIBUTES)) != 0 ) {
			ret |= SftpConstants.SSH_FXF_READ;
		}
		if( (access & (SftpConstants.ACE4_WRITE_DATA | SftpConstants.ACE4_APPEND_DATA)) != 0 ) {
			ret |= SftpConstants.SSH_FXF_WRITE;
		}
		if( (flags & (SftpConstants.SSH_FXF_APPEND_DATA | SftpConstants.SSH_FXF_APPEND_DATA_ATOMIC)) != 0 ) {
			ret |= SftpConstants.SSH_FXF_WRITE | SftpConstants.SSH_FXF_APPEND;
		}
		switch (flags & SftpConstants.SSH_FXF_ACCESS_DISPOSITION) {
		case SftpConstants.SSH_FXF_CREATE_NEW: ret |= SftpConstants.SSH_FXF_CREAT | SftpConstants.SSH_FXF_EXCL; break;
		case SftpConstants.SSH_FXF_CREATE_TRUNCATE: ret |= SftpConstants.SSH_FXF_CREAT | SftpConstants.SSH_FXF_TRUNC; break;
		case SftpConstants.SSH_FXF_OPEN_OR_CREATE: ret |= SftpConstants.SSH_FXF_CREAT; break;
		case SftpConstants.SSH_FXF_TRUNCATE_EXISTING: ret |= SftpConstants.SSH_FXF_TRUNC; break;
		default: break;
		}
		return ret;
	}

	private void read(int id, SshBuffer p) throws IOException {
		FileHandle h = fileHandle(p.getString());
		long offset = p.getLong();
		int len = (int) Math.min(p.getUInt(), MAX_READ);
		if( offset < 0 ) {
			throw new Status(SftpConstants.SSH_FX_BAD_MESSAGE, "Bad offset");
		}
		if( offset >= h.raf.length() ) {
			status(id, SftpConstants.SSH_FX_EOF, "End of file");
			return;
		}
		h.raf.seek(offset);
		byte[] buf = new byte[len];
		int n = 0;
		while( n < len ) {
			int k = h.raf.read(buf, n, len-n);
			if( k <= 0 ) {
				break;
			}
			n += k;
		}
		if( n == 0 ) {
			status(id, SftpConstants.SSH_FX_EOF, "End of file");
			return;
		}
		send(new SshBuffer(n+16).putByte(SftpConstants.SSH_FXP_DATA).putInt(id).putString(buf, 0, n));
	}

	private void write(int id, SshBuffer p) throws IOException {
		FileHandle h = fileHandle(p.getString());
		long offset = p.getLong();
		byte[] data = p.getString();
		if( !h.writable ) {
			throw new Status(SftpConstants.SSH_FX_PERMISSION_DENIED, "Not open for writing");
		}
		if( offset < 0 ) {
			throw new Status(SftpConstants.SSH_FX_BAD_MESSAGE, "Bad offset");
		}
		h.raf.seek(h.append ? h.raf.length() : offset);
		h.raf.write(data, 0, data.length);
		ok(id);
	}

	private void close(int id, SshBuffer p) throws IOException {
		Object h = handles.remove(new String(p.getString(), java.nio.charset.StandardCharsets.ISO_8859_1));
		if( h == null ) {
			throw new Status(SftpConstants.SSH_FX_INVALID_HANDLE, "Bad handle");
		}
		if( h instanceof FileHandle ) {
			((FileHandle) h).close();
		}
		ok(id);
	}

	private void setStat(int id, SshBuffer p) throws IOException {
		FileSource f = followed(p.getStringUtf8());
		SftpAttrs a = SftpAttrs.read(p, version);
		writable();
		if( !f.exists() ) {
			throw new Status(SftpConstants.SSH_FX_NO_SUCH_FILE, "No such file");
		}
		// changing the size is a write
		FileLock lock = a.hasSize() ? lock(f) : null;
		try {
			apply(id, f, null, a);
		} finally {
			closeQuietly(lock);
		}
	}

	private void fsetStat(int id, SshBuffer p) throws IOException {
		FileHandle h = fileHandle(p.getString());
		SftpAttrs a = SftpAttrs.read(p, version);
		writable();
		apply(id, h.file, h.raf, a);
	}

	private void apply(int id, FileSource f, IRandomAccessStream raf, SftpAttrs a) throws IOException {
		if( a.hasSize() ) {
			if( raf != null ) {
				raf.setLength(a.getSize());
			} else {
				try (IRandomAccessStream r = f.getRandomAccessStream("rw")) {
					r.setLength(a.getSize());
				}
			}
		}
		if( a.hasPermissions() ) {
			setPermissions(f, a.getPermissions());
		}
		// Version 4+ may set one time without the other (the creation time is not kept)
		if( a.hasAccessTime() ) {
			f.setLastAccessTime(a.getAccessTime()*1000+a.getAccessTimeNanos()/1000000);
		}
		if( a.hasModifyTime() ) {
			f.setLastModifiedTime(a.getModifyTime()*1000+a.getModifyTimeNanos()/1000000);
		}
		if( a.hasOwner() || a.hasOwnerNames() ) {
			// Numeric owners mean nothing to a FileSource
			throw new Status(SftpConstants.SSH_FX_OP_UNSUPPORTED, "Changing the owner is not supported");
		}
		ok(id);
	}

	private static void setPermissions(FileSource f, int mode) throws IOException {
		f.setOwnerReadable((mode & 0400) != 0);
		f.setOwnerWritable((mode & 0200) != 0);
		f.setOwnerExecutable((mode & 0100) != 0);
		f.setGroupReadable((mode & 0040) != 0);
		f.setGroupWritable((mode & 0020) != 0);
		f.setGroupExecutable((mode & 0010) != 0);
		f.setOtherReadable((mode & 0004) != 0);
		f.setOtherWritable((mode & 0002) != 0);
		f.setOtherExecutable((mode & 0001) != 0);
	}

	// ------------------------------------------------------------------ directories

	private void openDir(int id, SshBuffer p) throws IOException {
		FileSource d = followed(p.getStringUtf8());
		if( !d.exists() ) {
			throw new Status(SftpConstants.SSH_FX_NO_SUCH_FILE, "No such file");
		}
		if( !d.isDirectory() ) {
			throw new Status(SftpConstants.SSH_FX_NOT_A_DIRECTORY, "Not a directory");
		}
		if( handles.size() >= MAX_HANDLES ) {
			throw new Status(SftpConstants.SSH_FX_FAILURE, "Too many open directories");
		}
		FileSource[] list = d.listFiles();
		if( list == null ) {
			throw new Status(SftpConstants.SSH_FX_FAILURE, "Can't list");
		}
		ArrayDeque<FileSource> entries = new ArrayDeque<FileSource>();
		for (FileSource e : list) {
			if( !StoreLocks.get().isLockFile(e) ) {
				entries.add(e);
			}
		}
		handle(id, new DirHandle(d, entries));
	}

	private void readDir(int id, SshBuffer p) throws IOException {
		Object o = handles.get(new String(p.getString(), java.nio.charset.StandardCharsets.ISO_8859_1));
		if( !(o instanceof DirHandle) ) {
			throw new Status(SftpConstants.SSH_FX_INVALID_HANDLE, "Bad handle");
		}
		DirHandle h = (DirHandle) o;
		List<Object[]> batch = new ArrayList<Object[]>();
		if( !h.dotsSent ) {
			h.dotsSent = true;
			SftpAttrs a = attributes(h.dir, true);
			batch.add(new Object[] {".", version == 3 ? longName(".", h.dir, a) : null, a});
			batch.add(new Object[] {"..", version == 3 ? longName("..", h.dir, a) : null, a});
		}
		while( batch.size() < DIR_BATCH && !h.entries.isEmpty() ) {
			FileSource e = h.entries.poll();
			try {
				SftpAttrs a = attributes(e, false);
				batch.add(new Object[] {e.getName(), version == 3 ? longName(e.getName(), e, a) : null, a});
			} catch (IOException | RuntimeException ex) {
				// gone or unreadable since the listing: left out
			}
		}
		if( batch.isEmpty() ) {
			status(id, SftpConstants.SSH_FX_EOF, "End of directory");
			return;
		}
		SshBuffer b = new SshBuffer().putByte(SftpConstants.SSH_FXP_NAME).putInt(id).putInt(batch.size());
		for (Object[] e : batch) {
			b.putString((String) e[0]);
			if( version == 3 ) {
				// Version 4+ has no long name: the owner names are in the attributes
				b.putString((String) e[1]);
			}
			((SftpAttrs) e[2]).write(b, version);
		}
		send(b);
	}

	private void mkdir(int id, SshBuffer p) throws IOException {
		FileSource d = notFollowed(p.getStringUtf8());
		SftpAttrs a = SftpAttrs.read(p, version);
		writable();
		if( d.exists() || isLink(d) ) {
			throw new Status(SftpConstants.SSH_FX_FILE_ALREADY_EXISTS, "File exists");
		}
		if( !d.mkdir() ) {
			throw new Status(SftpConstants.SSH_FX_FAILURE, "Can't create the directory");
		}
		if( a.hasPermissions() ) {
			setPermissions(d, a.getPermissions());
		}
		ok(id);
	}

	private void rmdir(int id, SshBuffer p) throws IOException {
		FileSource d = notFollowed(p.getStringUtf8());
		writable();
		if( d == root ) {
			throw new Status(SftpConstants.SSH_FX_PERMISSION_DENIED, "Permission denied");
		}
		if( !d.exists() ) {
			throw new Status(SftpConstants.SSH_FX_NO_SUCH_FILE, "No such file");
		}
		if( !d.isDirectory() || isLink(d) ) {
			throw new Status(SftpConstants.SSH_FX_NOT_A_DIRECTORY, "Not a directory");
		}
		FileSource[] list = d.listFiles();
		if( list != null && list.length > 0 ) {
			throw new Status(SftpConstants.SSH_FX_DIR_NOT_EMPTY, "Directory not empty");
		}
		if( !d.delete() ) {
			throw new Status(SftpConstants.SSH_FX_FAILURE, "Can't remove the directory");
		}
		ok(id);
	}

	private void remove(int id, SshBuffer p) throws IOException {
		FileSource f = notFollowed(p.getStringUtf8());
		writable();
		boolean link = isLink(f);
		if( !link && !f.exists() ) {
			throw new Status(SftpConstants.SSH_FX_NO_SUCH_FILE, "No such file");
		}
		if( !link && f.isDirectory() ) {
			throw new Status(SftpConstants.SSH_FX_FILE_IS_A_DIRECTORY, "Is a directory");
		}
		// not while another session writes it (a link itself is never written)
		FileLock lock = link ? null : lock(f);
		try {
			if( !f.delete() ) {
				throw new Status(SftpConstants.SSH_FX_FAILURE, "Can't remove the file");
			}
		} finally {
			closeQuietly(lock);
		}
		ok(id);
	}

	private void rename(int id, String from, String to, boolean replace) throws IOException {
		FileSource src = notFollowed(from);
		FileSource dst = notFollowed(to);
		writable();
		if( src == root || dst == root ) {
			throw new Status(SftpConstants.SSH_FX_PERMISSION_DENIED, "Permission denied");
		}
		if( !src.exists() && !isLink(src) ) {
			throw new Status(SftpConstants.SSH_FX_NO_SUCH_FILE, "No such file");
		}
		boolean dstExists = dst.exists() || isLink(dst);
		if( dstExists && !replace ) {
			throw new Status(SftpConstants.SSH_FX_FILE_ALREADY_EXISTS, "File exists");
		}
		// not while another session writes either file (links and directories aren't written)
		FileLock srcLock = isLink(src) || src.isDirectory() ? null : lock(src);
		FileLock into = null;
		try {
			into = isLink(dst) || dst.isDirectory() ? null : lock(dst);
			if( !src.renameTo(dst) ) {
				if( !(replace && dstExists && !dst.isDirectory() && src.renameTo(dst, true)) ) {
					throw new Status(SftpConstants.SSH_FX_FAILURE, "Can't rename");
				}
			}
		} finally {
			closeQuietly(into);
			closeQuietly(srcLock);
		}
		ok(id);
	}

	private void realpath(int id, SshBuffer p) throws IOException {
		send(name(id, canonicalPath(p.getStringUtf8())));
	}

	/** As POSIX and OpenSSH's sftp-server: most links followed in one name */
	private static final int MAX_LINKS = 40;

	/**
	 * The canonical path of a client's path, as OpenSSH's sftp-server answers REALPATH: "." and ".."
	 * are resolved and so is every symbolic link, a component at a time, so ".." after a link is the
	 * parent of where the link leads. A link that leads nowhere resolves to the name it points at. Only
	 * the last component may be missing (so a client can ask for the path of a file it is about to
	 * make); a missing directory before it is "no such file", as for OpenSSH, and so is a loop of links.
	 * <p>
	 * The answer is the client's path (the root is "/"). A link that leads outside the root is
	 * "permission denied", which doesn't say where it points, and ".." can't climb above "/".
	 */
	private String canonicalPath(String path) throws IOException {
		String rootCanonical = root.getCanonicalPath();
		FileSource current = root;
		int links = 0;
		String slashed = path.replace('\\', '/');
		Deque<String> todo = new ArrayDeque<String>(Arrays.asList(slashed.split("/")));
		while( !todo.isEmpty() ) {
			String seg = todo.pollFirst();
			if( seg.isEmpty() || seg.equals(".") ) {
				continue;
			}
			if( seg.equals("..") ) {
				// the parent of where we really are, and never above the root
				if( !current.getCanonicalPath().equals(rootCanonical) ) {
					FileSource up = current.getParentFile();
					if( up != null ) {
						current = up;
					}
				}
				continue;
			}
			FileSource next = current.getChild(seg);
			// a link leads to a name, which may itself be a link
			while( isLink(next) ) {
				if( ++links > MAX_LINKS ) {
					// what OpenSSH answers for a loop
					throw new Status(SftpConstants.SSH_FX_NO_SUCH_FILE, "No such file");
				}
				FileSource to = next.getLinkedTo();
				if( to == null || !root.isChildOfMine(to) ) {
					throw new Status(SftpConstants.SSH_FX_PERMISSION_DENIED, "Permission denied");
				}
				next = to;
			}
			// only the last component may be missing: "new" is fine, "new/file" and "new/" are not
			boolean last = todo.isEmpty() && !slashed.endsWith("/");
			if( !last && !next.exists() ) {
				throw new Status(SftpConstants.SSH_FX_NO_SUCH_FILE, "No such file");
			}
			current = next;
		}
		String virtual = virtualPath(current);
		if( virtual == null ) {
			throw new Status(SftpConstants.SSH_FX_PERMISSION_DENIED, "Permission denied");
		}
		return virtual;
	}

	// ------------------------------------------------------------------ links

	private void readlink(int id, SshBuffer p) throws IOException {
		FileSource f = notFollowed(p.getStringUtf8());
		FileSource target = f.getLinkedTo();
		if( target == null ) {
			throw new Status(SftpConstants.SSH_FX_FAILURE, "Not a link");
		}
		String virtual = virtualPath(target);
		if( virtual == null ) {
			// Don't tell where outside the root it points
			throw new Status(SftpConstants.SSH_FX_PERMISSION_DENIED, "Permission denied");
		}
		send(name(id, virtual));
	}

	/**
	 * @return the client's path for a file, or null if it isn't inside the root
	 */
	private String virtualPath(FileSource f) throws IOException {
		if( !root.isChildOfMine(f) ) {
			return null;
		}
		String r = root.getCanonicalPath();
		String c = f.getCanonicalPath();
		String rel = c.substring(r.length()).replace('\\', '/');
		return normalize(rel);
	}

	/**
	 * Which of the two paths of a version 4+ SYMLINK or LINK is the new link. The drafts put
	 * the link first, but OpenSSH (version 3) and MINA (every version) put the target first,
	 * so it is decided by what exists: the link must not, the target usually does. If that
	 * doesn't tell, the target is first.
	 *
	 * @return target, link
	 */
	private String[] targetAndLink(String first, String second) throws IOException {
		FileSource a = notFollowed(first);
		FileSource b = notFollowed(second);
		boolean aExists = a.exists() || isLink(a);
		boolean bExists = b.exists() || isLink(b);
		if( !aExists && bExists ) {
			return new String[] {second, first};
		}
		return new String[] {first, second};
	}

	/**
	 * A NAME reply with one name (and no attributes)
	 */
	private SshBuffer name(int id, String name) {
		SshBuffer b = new SshBuffer().putByte(SftpConstants.SSH_FXP_NAME).putInt(id).putInt(1).putString(name);
		if( version == 3 ) {
			b.putString(name);
		}
		return SftpAttrs.NONE.write(b, version);
	}

	/**
	 * Create the symbolic link linkPath to target, which must be inside the root.
	 */
	private void symlink(int id, String target, String linkPath) throws IOException {
		writable();
		FileSource link = notFollowed(linkPath);
		String n = normalize(linkPath);
		String vtarget = target.startsWith("/") ? target : n.substring(0, n.lastIndexOf('/')+1)+target;
		FileSource t = followed(vtarget);
		if( link.exists() || isLink(link) ) {
			throw new Status(SftpConstants.SSH_FX_FILE_ALREADY_EXISTS, "File exists");
		}
		root.getFileSourceFactory().createSymbolicLink(link, t);
		ok(id);
	}

	private void hardlink(int id, String existingPath, String linkPath) throws IOException {
		FileSource existing = notFollowed(existingPath);
		FileSource link = notFollowed(linkPath);
		writable();
		if( !existing.exists() ) {
			throw new Status(SftpConstants.SSH_FX_NO_SUCH_FILE, "No such file");
		}
		if( link.exists() ) {
			throw new Status(SftpConstants.SSH_FX_FILE_ALREADY_EXISTS, "File exists");
		}
		root.getFileSourceFactory().createLink(link, existing);
		ok(id);
	}

	/**
	 * version-select (draft 13, 5.5): a client that started with version 3 moves to a later one.
	 */
	private void selectVersion(int id, String wanted) throws IOException {
		int v;
		try {
			v = Integer.parseInt(wanted.trim());
		} catch (NumberFormatException e) {
			v = -1;
		}
		if( version != SftpConstants.SFTP_VERSION || v < SftpConstants.SFTP_VERSION || v > SftpConstants.SFTP_MAX_VERSION ) {
			// The draft says to close the channel: a client that can't speak the version can't go on
			status(id, SftpConstants.SSH_FX_FAILURE, "Can't select version "+wanted);
			throw new IOException("Bad version-select "+wanted);
		}
		version = v;
		ok(id);
	}

	private void extended(int id, SshBuffer p) throws IOException {
		String name = p.getStringUtf8();
		switch (name) {
		case SftpConstants.EXT_POSIX_RENAME:
			rename(id, p.getStringUtf8(), p.getStringUtf8(), true);
			return;
		case SftpConstants.EXT_HARDLINK: {
			String existing = p.getStringUtf8();
			hardlink(id, existing, p.getStringUtf8());
			return;
		}
		case SftpConstants.EXT_FSYNC:
			fileHandle(p.getString());
			// Writes go straight to the FileSource; nothing is held back here
			ok(id);
			return;
		default:
			status(id, SftpConstants.SSH_FX_OP_UNSUPPORTED, "Unsupported extension "+name);
		}
	}

	// ------------------------------------------------------------------ attributes

	private SftpAttrs attributes(FileSource f, boolean follow) throws IOException {
		if( !follow && isLink(f) ) {
			long mtime = 0;
			try {
				mtime = f.lastModified()/1000;
			} catch (IOException | RuntimeException e) {
				// a dangling link
			}
			return SftpAttrs.NONE.withSize(0).withPermissions(S_IFLNK | 0777).withTimes(mtime, mtime);
		}
		if( !f.exists() ) {
			throw new Status(SftpConstants.SSH_FX_NO_SUCH_FILE, "No such file");
		}
		boolean dir = f.isDirectory();
		int mode = (dir ? S_IFDIR : S_IFREG)
				| (f.canOwnerRead() ? 0400 : 0) | (f.canOwnerWrite() ? 0200 : 0) | (f.canOwnerExecute() ? 0100 : 0)
				| (f.canGroupRead() ? 0040 : 0) | (f.canGroupWrite() ? 0020 : 0) | (f.canGroupExecute() ? 0010 : 0)
				| (f.canOtherRead() ? 0004 : 0) | (f.canOtherWrite() ? 0002 : 0) | (f.canOtherExecute() ? 0001 : 0);
		long size = dir ? 0 : f.length();
		long mtimeMs = f.lastModified();
		long atimeMs = mtimeMs;
		try {
			long a = f.lastAccessTime();
			if( a > 0 ) {
				atimeMs = a;
			}
		} catch (IOException | RuntimeException e) {
			// not every file system has it
		}
		SftpAttrs ret = SftpAttrs.NONE.withSize(size).withPermissions(mode);
		if( version == 3 ) {
			return ret.withTimes(atimeMs/1000, mtimeMs/1000);
		}
		// Version 4+: milliseconds, and the owner's names (there is no long name)
		ret = ret.withTimes(Math.floorDiv(atimeMs, 1000), (int) Math.floorMod(atimeMs, 1000)*1000000,
				Math.floorDiv(mtimeMs, 1000), (int) Math.floorMod(mtimeMs, 1000)*1000000);
		String ownerName = null;
		String groupName = null;
		try {
			UserPrincipal u = f.getOwner();
			if( u != null ) {
				ownerName = u.getName();
			}
		} catch (IOException | RuntimeException e) {
			// not known
		}
		try {
			GroupPrincipal g = f.getGroup();
			if( g != null ) {
				groupName = g.getName();
			}
		} catch (IOException | RuntimeException e) {
			// not known
		}
		if( ownerName != null ) {
			//  A file system without groups (Windows) has no group to name: "-", as the ls -l
			//  line does, so the owner is still given.
			ret = ret.withOwnerNames(ownerName, groupName != null ? groupName : "-");
		}
		return ret;
	}

	/**
	 * "ls -l" style: what version 3 clients show (it is the only place for owner and group names).
	 */
	private static String longName(String name, FileSource f, SftpAttrs a) {
		String owner = "-";
		String group = "-";
		try {
			UserPrincipal u = f.getOwner();
			if( u != null ) {
				owner = u.getName();
			}
			GroupPrincipal g = f.getGroup();
			if( g != null ) {
				group = g.getName();
			}
		} catch (IOException | RuntimeException e) {
			// not known
		}
		int m = a.getPermissions();
		StringBuilder perms = new StringBuilder();
		int type = m & 0170000;
		perms.append(type == S_IFDIR ? 'd' : type == S_IFLNK ? 'l' : '-');
		String rwx = "rwxrwxrwx";
		for (int i = 0; i < 9; i++) {
			perms.append((m & (0400 >> i)) != 0 ? rwx.charAt(i) : '-');
		}
		long mtime = a.getModifyTime()*1000;
		boolean recent = Math.abs(System.currentTimeMillis()-mtime) < 180L*24*60*60*1000;
		String date = new SimpleDateFormat(recent ? "MMM dd HH:mm" : "MMM dd  yyyy", Locale.US).format(new Date(mtime));
		return String.format(Locale.US, "%s %3d %-8s %-8s %8d %s %s", perms, 1, owner, group, a.getSize(), date, name);
	}

	// ------------------------------------------------------------------ replies

	private FileHandle fileHandle(byte[] id) throws Status {
		Object h = handles.get(new String(id, java.nio.charset.StandardCharsets.ISO_8859_1));
		if( !(h instanceof FileHandle) ) {
			throw new Status(SftpConstants.SSH_FX_INVALID_HANDLE, "Bad handle");
		}
		return (FileHandle) h;
	}

	private void handle(int id, Object h) throws IOException {
		String key = Integer.toString(nextHandle++);
		handles.put(key, h);
		send(new SshBuffer().putByte(SftpConstants.SSH_FXP_HANDLE).putInt(id).putString(key.getBytes(java.nio.charset.StandardCharsets.ISO_8859_1)));
	}

	private void attrs(int id, SftpAttrs a) throws IOException {
		send(a.write(new SshBuffer().putByte(SftpConstants.SSH_FXP_ATTRS).putInt(id), version));
	}

	private void ok(int id) throws IOException {
		status(id, SftpConstants.SSH_FX_OK, "");
	}

	private void status(int id, int code, String message) throws IOException {
		// A code the client's version doesn't have becomes the nearest one it does
		send(new SshBuffer().putByte(SftpConstants.SSH_FXP_STATUS).putInt(id).putInt(SftpConstants.statusFor(code, version)).putString(message).putString(""));
	}

	private void send(SshBuffer payload) throws IOException {
		int len = payload.available();
		byte[] head = {(byte) (len >>> 24), (byte) (len >>> 16), (byte) (len >>> 8), (byte) len};
		// One write per packet, so header and body go out together
		byte[] packet = new byte[4+len];
		System.arraycopy(head, 0, packet, 0, 4);
		System.arraycopy(payload.array(), payload.readPosition(), packet, 4, len);
		out.write(packet);
	}
}
