# parley-ssh

SSH for **Parley**, a family of Java libraries for implementing internet protocols: an SSH client
and server (RFC 4251-4254) built on `parley-net`'s non-blocking `nio` package, with SFTP client and
server, and what OpenSSH users expect: certificates, agents, port forwarding and security keys.
It is tested against OpenSSH, Apache MINA SSHD and JSch.

| Package | What it holds |
|---|---|
| `us.bringardner.parley.ssh.algorithms` | Key exchange, host key, cipher and MAC plug-ins; certificates and security keys |
| `us.bringardner.parley.ssh.transport` | Packets, key exchange, re-keying (shared by client and server) |
| `us.bringardner.parley.ssh.connection` | Channels with flow control, port and agent forwarding channels (shared) |
| `us.bringardner.parley.ssh.client` | `SshClient`, `ClientSession`, `known_hosts`, login methods, SSH agent |
| `us.bringardner.parley.ssh.server` | `SshServer`, host keys, login methods, exec / shell / subsystem plug-ins |
| `us.bringardner.parley.ssh.sftp` | SFTP client |
| `us.bringardner.parley.ssh.sftp.server` | SFTP server: each user's root is any `FileSource` (local disk, memory, another SFTP server...) |
| `us.bringardner.parley.ssh.keys` | Reading and writing key files, key revocation lists |

## Features

**Algorithms** (strongest first): curve25519, ECDH and Diffie-Hellman group 14/16 key exchange;
Ed25519, ECDSA and RSA (SHA-2) keys; chacha20-poly1305, AES-GCM and AES-CTR ciphers; HMAC-SHA2
(encrypt-then-MAC); zlib compression; strict key exchange (the Terrapin fix); re-keying. SHA-1
algorithms are known but only used when turned on by name.

**Keys**: OpenSSH (including passphrase protected), PKCS#8, traditional PEM and key store files are
read; OpenSSH and PKCS#8 files are written.

**Client**
- Login with password, keyboard-interactive, public keys, OpenSSH certificates, or the keys of an
  SSH agent (`ssh-agent`, OpenSSH's Windows agent, PuTTY's Pageant)
- Host keys checked against `known_hosts` (hashed names, wildcards, `@revoked`, `@cert-authority`
  for host certificates) and key revocation lists, optionally after a DNS lookup of the host's SSHFP
  records (`HostKeyVerifiers.withLookup`, with parley-dns)
- exec, shells with a pseudo terminal, subsystems, local and remote port forwarding (`-L`, `-R`),
  agent forwarding (`-A`), keep-alives
- SFTP versions 3 to 6, with several reads and writes in flight
- An `ssh` command for the command line (`Ssh`, see [The ssh command](#the-ssh-command))

**Server**
- Login with password and keyboard-interactive through the access control list every Parley server
  uses, with `authorized_keys` files (including their options: `command=`, `from=`, `no-pty`,
  `permitopen=`, `restrict`, `cert-authority`...), with user certificates from trusted certificate
  authorities, and with FIDO security keys (`sk-ecdsa`, `sk-ed25519`; touch and PIN rules as in
  OpenSSH)
- Host keys made once and kept, from files or a key store, with host certificates
- Revoked keys and certificates refused (OpenSSH key revocation lists or key lists)
- The shared login limits: failures before the connection is closed, a delay after each, and a
  time limit for logging in
- What runs is up to plug-ins: commands, a shell, subsystems such as SFTP. `ProcessCommandFactory`
  and `ProcessShellFactory` run operating system commands, on a real pseudo terminal when pty4j is
  on the class path
- Port forwarding (refused unless a forwarding filter allows it) and agent forwarding
- SFTP versions 3 to 6 on any `FileSource`, which keeps each user inside their root, also through
  symbolic links (see [Links](#links-in-the-sftp-server))

Requires Java 11 or later. Some features need more: Ed25519 needs Java 15, and SSH agents on Unix
(and agent forwarding) need Java 16 (Unix domain sockets).

```xml
<dependency>
    <groupId>us.bringardner.parley</groupId>
    <artifactId>parley-ssh</artifactId>
    <version>1.0.0</version>
</dependency>
```

Depends on `parley-net` (which brings in `parley-core` and `parley-io`). Optional dependencies, added
by you when you need them:

| Dependency | For |
|---|---|
| `us.bringardner.parley:parley-files` | The SFTP server (`us.bringardner.parley.ssh.sftp.server`) |
| `org.jetbrains.pty4j:pty4j` | Pseudo terminals for operating system commands and shells |

> parley-ssh was previously `us.bringardner:bjl_net_ssh` (BjlSsh), with packages under
> `us.bringardner.net.ssh`. Moving over means changing the dependency and replacing
> `us.bringardner.net.ssh` with `us.bringardner.parley.ssh` in imports and in property names that
> start with a class name.

## Client

```java
try (SshClient client = new SshClient()) {
    client.setHostKeyVerifier(KnownHosts.userFile());          // ~/.ssh/known_hosts
    ClientSession s = client.connectAndWait("example.com", 22);
    s.authenticateAndWait("tony", PublicKeyAuth.fromAgent(SshAgent.connect()));
    System.out.print(s.exec("uname -a", null, 30000).getStdoutText());

    try (SftpClient sftp = SftpClient.open(s)) {
        for (SftpDirEntry e : sftp.list(".")) {
            System.out.println(e.getLongName());
        }
    }
}
```

`new PublicKeyAuth(SshKeyLoader.load(file, passphrase))` logs in with a key file, and
`addCertificate(key, SshCertificate.load(certFile))` adds its certificate.

**Host keys in DNS (SSHFP).** `HostKeyVerifiers.withLookup(lookup, fallback)` asks a lookup first
(OpenSSH's `VerifyHostKeyDNS`): `TRUE` trusts the key, `FALSE` refuses it, `null` (no records, not
secure, unavailable) leaves it to the fallback, such as `known_hosts`. parley-ssh doesn't depend on
parley-dns; with it on the class path and a validating resolver (`-Dparley.dns.dnssecValidation=true`):

```java
client.setHostKeyVerifier(HostKeyVerifiers.withLookup((host, blob) -> {
    switch (SshfpVerifier.verify(host, blob)) {
        case MATCH: return Boolean.TRUE;
        case MISMATCH: case BOGUS: return Boolean.FALSE;
        default: return null;                         // NO_RECORDS, INSECURE, TEMPFAIL
    }
}, KnownHosts.userFile()));
```

Only a DNSSEC-validated answer proves anything, so `SshfpVerifier` reports unsigned answers as
`INSECURE`. parley-dns's `SshfpTool` prints the records to publish for a server's keys.

### The ssh command

`us.bringardner.parley.ssh.client.Ssh` is a command-line client, used like OpenSSH's `ssh`:

```
java -cp <class path> us.bringardner.parley.ssh.client.Ssh [options] [user@]host [command]
```

The class path needs only parley-ssh, parley-net, parley-core and parley-io (their jars, or their
`target/classes` folders); `mvn dependency:build-classpath` prints it. It runs on Java 11 or later, but
Ed25519 keys need Java 15, and SSH agents on Unix (and agent forwarding) need Java 16.

#### Supported

**Command line**

| Option | What it does |
|---|---|
| `-p port`, `-l user`, `user@host` | Where to log in |
| `-i file` | Identity (key) file; may be repeated |
| `-F file` | Config file to read instead of the usual ones (`none` for none) |
| `-o Keyword=value` | Any supported config keyword (below); keywords for missing features are accepted and ignored |
| `-J [user@]host[:port],...` | Jump hosts (ProxyJump); `-J none` turns a configured one off |
| `-t`, `-tt`, `-T` | Pseudo terminal: if stdin is a terminal, always, never |
| `-N`, `-n`, `-s` | No command (forwarding only), stdin from nowhere, the command is a subsystem (`-s host sftp`) |
| `-L`, `-R` `[bind_address:]port:host:hostport` | Local and remote TCP port forwarding (`-R` with port 0 prints the port the server chose) |
| `-A`, `-a` | Agent forwarding on, off |
| `-C`, `-c ciphers`, `-m macs` | Compression; cipher and MAC lists (`+`, `-` and `^` prefixes as in OpenSSH) |
| `-e char` | Escape character (`^X` form, or `none`) |
| `-q`, `-v` (`-vv`), `-V` | Quiet, verbose (debug), version |
| `-x`, `-k` | Accepted; they turn off X11 and GSSAPI, which aren't there anyway |

Options may come before or after the host, and be grouped (`-tt`, `-vA`, `-p2222`); after the host,
the first other word starts the command (or `--`).

**Config files**: `~/.ssh/config` then `/etc/ssh/ssh_config` (or the `-F` file), first value wins as
in OpenSSH. Host blocks (patterns, `!` negation), `Match all`, `Match host`, `Match originalhost`,
`Match final`, and `Include` (wildcards in file and folder names). Keywords:

| Area | Keywords |
|---|---|
| Where | HostName, User, Port, ProxyJump, ProxyCommand (`%h %p %r %n`), ConnectTimeout, ServerAliveInterval, ServerAliveCountMax |
| Host keys | StrictHostKeyChecking, UserKnownHostsFile, GlobalKnownHostsFile, HashKnownHosts, HostKeyAlias, HostKeyAlgorithms |
| Login | IdentityFile, CertificateFile, IdentitiesOnly, IdentityAgent, PreferredAuthentications, PubkeyAuthentication, KbdInteractiveAuthentication, PasswordAuthentication, NumberOfPasswordPrompts, BatchMode |
| Session | RequestTTY, SendEnv, SetEnv, ForwardAgent, LocalForward, RemoteForward, ExitOnForwardFailure, EscapeChar, LogLevel |
| Algorithms | Ciphers, MACs, KexAlgorithms, Compression |

Tokens `%d %h %n %p %r %u %l` and `~` are expanded in file names.

**Host keys**: checked against the known_hosts files as OpenSSH does: hashed names, wildcards,
`@cert-authority` (host certificates) and `@revoked`. A new host is asked about (`yes`, `no` or its
fingerprint) and saved, hashed unless `HashKnownHosts no`. A revoked key is always refused, and so is
a changed key, except with `StrictHostKeyChecking no`: then, as OpenSSH, the connection goes on after
the warning but with password and keyboard-interactive login, agent forwarding and port forwarding
turned off (a key login still works), and the known key is left as it is. StrictHostKeyChecking `ask`
(default), `yes`, `accept-new`, `no`.

**Login**, in OpenSSH's order:
1. The SSH agent's keys (`SSH_AUTH_SOCK` or IdentityAgent).
2. Key files: OpenSSH, PKCS#8 and PEM; RSA, ECDSA and Ed25519; with their certificates (`-cert.pub`,
   CertificateFile). A passphrase is asked only once the server said it would take the key (when the
   `.pub` file is next to it), three tries.
3. keyboard-interactive, then password (NumberOfPasswordPrompts, default 3).

Questions are asked on the terminal, on `/dev/tty` when stdin is redirected, else with `SSH_ASKPASS`,
else on stdin (an IDE's console; a line says so).

**Sessions**: a shell or `-t` gets a pseudo terminal with the local terminal in raw mode (`stty`) and
window size changes sent; the terminal is put back on every exit. Escapes at the start of a line:
`~.` disconnect, `~?` help, `~#` forwardings, `~~` a `~`. The exit status is the remote command's, 255
when ssh failed (OpenSSH's messages). Without a terminal, a shell gets no prompt and a line says so.

#### Not supported

| Missing | Notes |
|---|---|
| `-D` / DynamicForward (SOCKS proxy) | |
| `-W host:port` (stdio forwarding) | ProxyJump covers the usual use |
| `-f` (background after login) | |
| Connection sharing: `-M`, `-S`, `-O`, ControlMaster, ControlPath, ControlPersist | Accepted in config files and ignored: each run logs in again |
| X11 forwarding: `-X`, `-Y`, ForwardX11 | Not in the library either (see below) |
| Tunnel devices (`-w`), Unix socket forwarding, `-R` dynamic (SOCKS) forwarding | |
| GSSAPI/Kerberos and host-based login (`-K`) | Servers that offer them still let you log in another way |
| FIDO security key files (`-sk` keys), PKCS#11 | Security keys work through an agent |
| `-4`, `-6`, `-b`, `-B`, `-E`, `-G`, `-g`, `-I`, `-Q`, `-y` | Rejected with "not supported" |
| `Match exec`, `user`, `localuser`, `canonical`, `tagged`; CanonicalizeHostname | A Match block with these is skipped |
| VerifyHostKeyDNS, UpdateHostKeys, CheckHostIP, RevokedHostKeys, AddKeysToAgent | Ignored; SSHFP is in the library (`HostKeyVerifiers.withLookup`) |
| Password change requests from the server | That login method fails, the next is tried |
| `~^Z`, `~C`, `~R`, `~B`, `~&` escapes | |
| Raw mode and window size on Windows | Works without a pseudo terminal; `-tt` gives one, but keys go line by line |

Differences from OpenSSH: `IdentitiesOnly yes` doesn't use the agent at all (OpenSSH uses its keys that
match the identity files); unknown keywords in `-o` are an error, in config files a `-v` message.

## Server

```java
SshServer server = new SshServer(2222);
server.setHostKeyProvider(HostKeyProviders.generated(new File("/var/myapp/ssh")));
server.setPublicKeyAuthenticator(AuthorizedKeysAuthenticator.forHomes(new File("/home")));
server.addSubsystem(SftpSubsystemFactory.forRoot(root));      // root: any FileSource
server.startAndWait(10000);
```

Without a password authenticator the server uses its access control list for passwords, as every
Parley server does.

### Properties

Settings can also be given as properties: system properties, or a properties file named after the
class on the class path, each named with the server's prefix, `parley.ssh`: the table's `port` is
`parley.ssh.port`, and so on.

| Property | What it does | Default |
|---|---|---|
| `port` | The port to listen on, when the server is made without one | 9200 (Parley's default: give 22 or another port) |
| `bindAddress` | The address to listen on | all addresses |
| `maxConnections` | Connections at a time; more are refused | no limit |
| `backlog` | Connections waiting to be accepted | the system's |
| `tcpNoDelay`, `keepAlive` | TCP_NODELAY and SO_KEEPALIVE on connections | off |
| `authenticationProvider` | Class name of the access control list (users, passwords, permissions), e.g. `us.bringardner.parley.net.server.FileBasedAcl` | none |
| `hostKeyDir` | Where host keys are made and kept (with `*-cert.pub` host certificates) | the working directory |
| `keyStoreName`, `keyStorePassword`, `keyStoreType` | Host keys from a key store's RSA and EC entries instead of `hostKeyDir` | not used |
| `shellFactory` | Class name of the `IShellFactory` that answers "shell" requests, or `none` | fsh when it is on the class path, else none (shells refused) |
| `revokedKeys` | A key revocation list or list of keys that can't log in | none |
| `maxLoginAttempts` | Failed logins before the connection is closed | 6 |
| `loginFailureDelay` | Milliseconds before a failed login is answered | 250 |
| `loginTimeLimit` | Milliseconds a connection has to log in | 120000 |

Properties of other Parley servers that an SSH server ignores: `secure` (SSH encrypts itself and
never uses TLS), `socketTimeout`, `acceptTimeout`, `soLinger` and `isSoLinger` (they are for
servers that block a thread per connection).

### Settings in code

| `SshServer` method | What it does | Default |
|---|---|---|
| `setPasswordAuthenticator`, `setPublicKeyAuthenticator`, `setAuthMethods` | How users log in | the access control list for passwords |
| `setHostKeyProvider` | Where host keys (and host certificates) come from | `hostKeyDir` or the key store |
| `setCommandFactory`, `setShellFactory`, `addSubsystem` | What "exec", "shell" and subsystem requests run | refused, except shells: fsh when it is on the class path |
| `setForwardingFilter` | Which port forwardings are allowed (`ForwardingFilters.localOnly()`...) | none: refused |
| `setAgentForwardingAllowed` | Whether clients may forward their agent | yes, as OpenSSH |
| `setRevokedKeys` | Keys and certificates that can't log in | none |
| `setSecurityKeyTouchRequired`, `setSecurityKeyVerifyRequired` | Security keys must always be touched / verified with a PIN | no (the key's options decide) |
| `setAlgorithms` | The algorithms offered (`SshAlgorithms.defaults()`, then `setCiphers(...)`...) | the strongest, no SHA-1 |
| `setBanner` | Text shown before login | none |
| `setMaxChannelsPerSession` | Channels one connection may have open | 10 |
| `setMaxIdleTime` | Milliseconds without traffic before a connection is closed | 24 hours |
| `setMaxLoginAttempts`, `setLoginFailureDelay`, `setLoginTimeLimit` | The login limits (as the properties) | 6, 250 ms, 2 minutes |

| Client method | What it does | Default |
|---|---|---|
| `SshClient.setHostKeyVerifier` | How host keys are checked: `KnownHosts` (with `setPolicy`: reject, accept new, accept), `HostKeyVerifiers.only(...)` | `~/.ssh/known_hosts`, unknown hosts refused |
| `KnownHosts.setRevokedHostKeys` | Host keys and certificates to refuse | none |
| `SshClient.setAlgorithms` | The algorithms offered | the strongest, no SHA-1 |
| `SshClient.setKeepAliveInterval` | Milliseconds between keep-alives on idle sessions | off |
| `ClientSession.setAgentForwarding` | Lets the server use an SSH agent through the session | off |
| `SftpClient.setTimeout` | Milliseconds a request waits for its reply | 60000 |
| `SftpClient.setChunkSize`, `setOutstanding` | Bytes per read or write, and requests in flight | 32 KB, 16 |

**Running operating system commands is opt-in, and they run as the account the server runs as,
whoever logged in.** Give `ProcessCommandFactory` and `ProcessShellFactory` only to users who may do
anything that account can (with an access control list, they need the "exec" or "shell"
permission).

### Running as a service

`SshServer`'s `main` runs a server until the process is stopped, for systemd, launchd or a Windows
service:

```sh
java -cp 'parley-ssh.jar:...' us.bringardner.parley.ssh.server.SshServer [-Dname=value ...]
```

It runs with parley-net's `ServerMain.run`, as every Parley server does: its settings come from the
command line and a settings file (the command line wins), then it sets the server up from them:

| What | Setting | Default |
|---|---|---|
| Settings file | `parley.ssh.configFile` | `CONF/parley-ssh.properties`, when it is there |
| Port | `parley.ssh.port` | 22 |
| Host keys (made the first time, folder readable by its owner only) | `parley.ssh.hostKeyDir` | `CONF/ssh` |
| Users' homes | `parley.ssh.homes` | `/home` (macOS `/Users`, Windows `C:\Users`) |
| Trusted user CAs (OpenSSH's TrustedUserCAKeys) | `parley.ssh.trustedUserCaKeys` | `CONF/ssh/trusted_user_ca_keys`, when it is there |
| Passwords | `parley.ssh.authenticationProvider` | none: no password logins |

`CONF` is the folder of Parley's administrator file: `/etc/parley` (Windows `%ProgramData%\Parley`),
or the folder of the file the `PARLEY_CONF` environment variable names. Users log in with a password
(the access control list), a key in `HOMES/USER/.ssh/authorized_keys`, or a certificate signed by a
trusted CA. With parley-files on the class path, SFTP puts each user in their home: the access
control list's `userRoot` parameter (the one FTP uses), else `HOMES/USER`; a user with neither
folder gets no SFTP. The shell is fsh when it is on the class path (`shellFactory`).

The process exits with 1 when the server can't start (a port in use, a missing CA file, an access
control list or shell that can't be made), so the service manager sees it. Stopping the process
(SIGTERM) stops the server; under systemd, give `SuccessExitStatus=143`.

**Every session runs as the service's account, whoever logged in**: fsh and SFTP see that account's
files and permissions. Run the service as an account made for it, not as root (on Linux, port 22
needs `AmbientCapabilities=CAP_NET_BIND_SERVICE` in the systemd unit, or a port above 1023).

## Links in the SFTP server

SFTP knows about links, so the server hides nothing: a client can see a link (`LSTAT`, a directory
listing), read it (`READLINK`) and make one (`SYMLINK`, `LINK`, `hardlink@openssh.com`). What a link
does is what it does on the file system under the user's root, because the server asks the root's
`FileSource` for it (see [parley-files](https://github.com/parley-project/parley-files#links) for what
each file system supports).

> This is a different model from the FTP server's in [parley-ftp](https://github.com/parley-project/parley-ftp#links).
> FTP has no idea of a link, so that server hides links from its clients and replaces a link when one is
> written to. SFTP sees them, so a write goes through.

| Request | What happens |
|---|---|
| `LSTAT`, a directory listing | A link is a link: the symbolic link type (`l` in a version 3 long name), size 0, mode `0777`. A link that leads nowhere is listed too. |
| `STAT`, `FSTAT` | Follows the link: the type, size, times and permissions of what it leads to. A link that leads nowhere is "no such file". |
| `OPEN`, `READ`, `WRITE`, `OPENDIR` | Follows the link. **A write changes the file it leads to** and the link stays a link. Through a linked directory it is the same (`/dirlink/new.txt` is made in the directory it leads to). |
| `SETSTAT`, `FSETSTAT` | Applies to the file it leads to: truncate, mode and times. |
| `REMOVE` | Removes the **link** only, also a link to a directory. What it led to is untouched. |
| `RMDIR` | Refused for a link (use `REMOVE`). Version 3 has no "not a directory" status, so the client sees a plain failure. |
| `RENAME`, `posix-rename` | Moves the **link**. What it led to is untouched. |
| `REALPATH` | The canonical path, as OpenSSH's `sftp-server` answers it: `.` and `..` are resolved and **so is every link**, a component at a time (so `..` after a link is the parent of where the link leads). A link that leads nowhere resolves to the name it points at. Only the last component may be missing: a missing directory before it, and a loop of links, are "no such file". The answer is the client's path, and a link that leads outside the root is "permission denied". |
| `READLINK` | The target, as the client's path (`/real.txt`, not the server's). A link that leads outside the root is "permission denied", which doesn't say where it points. |
| `SYMLINK` (versions 3 to 5), `LINK` (version 6) | Makes a symbolic link, or a hard link if the request says so. The link must not exist and its target must be inside the root. OpenSSH sends the target first; for versions 4 and up, where the drafts differ, the one that doesn't exist is taken to be the link. |
| `hardlink@openssh.com` | Makes a hard link to a file that exists. |
| `MKDIR` on a link's name | "File exists". |

### The root is a sandbox

Every path a client uses is checked with `FileSource.isChildOfMine`, which compares canonical paths
(links resolved), so nothing outside the user's root can be read, written or listed:

- `..` stops at `/`.
- A link that leads outside the root can be **seen** (`LSTAT`, a listing) and **removed or renamed**
  (those act on the link), but not **followed**: `STAT`, `OPEN`, `OPENDIR` and `READLINK` through it
  are "permission denied".
- A link can't be made to a target outside the root, nor through a link that leads outside.
- Error messages don't contain the server's real paths.

There is **no setting** that lets a link lead outside the root, unlike the FTP server's
`symlinkPolicy`. To share a directory with every user, make it part of each user's root (an
`ISftpRootProvider` can build one) and don't link to it.

### Read-only mode and other roots

- `SftpSubsystemFactory.setReadOnly(true)` refuses every change: making, removing or renaming a link,
  and writing through one (`Read-only`). Reading through a link still works.
- A root can be any `FileSource`, and links follow that file system's rules. A memory file system root
  has links; a root whose file system can't make them answers `SYMLINK` and `LINK` with a plain
  failure (the server doesn't send the reason, which could hold a real path).

These behaviors are tested in `SftpServerLinksTest` (and the sandbox in `SftpServerTest`).

## Writers in the SFTP server

Two sessions never write one file at once, whether they are on this server or on others that share
the store:

- A file open for writing (or for truncating) holds its lock until the handle is closed or the session
  ends. While another session holds it, opening it for writing, removing it, renaming it (or renaming
  another file over it) and changing its size are refused at once with `SSH_FX_LOCK_CONFLICT`
  (`SSH_FX_FAILURE` before version 5) and "The file is being written by another session". A client can
  try again later. One session may open a file for writing more than once.
- Reading takes no lock: a reader sees the file as it is being written.
- The locks are parley-net's (`StoreLocks`): one lock domain per root, shared with the other servers in
  the JVM that serve it (parley-ftp's FTP server, say), so an FTP upload and an SFTP write of one file
  keep out of each other too. A root inside one already in use shares its domain.
- How many servers share the store is the system property `parley.ssh.sftp.sharedStore`: `off` (the default:
  this server alone; the first session claims the store and a server elsewhere that claims it alone is
  refused), `host` (several on one machine) or `cluster` (several anywhere). With `host` or `cluster`,
  every server must serve the same root, where the locks are kept. `parley.ssh.sftp.serverId` names this
  server among them (default: the host and the process).
- The locks are kept in the root, in `.parley-net-locks`. The server hides it: it isn't listed and can't
  be reached, so no client can change it.
- Not covered: a directory removed or renamed while a file in it is being written (the write then fails
  as it would without locks), and two names for one file on a file system that ignores case.

Tested in `SftpLocksTest`.

## Shells

`SshServer` answers "shell" requests (an interactive `ssh host`) through an `IShellFactory`, set in
code or named with the `shellFactory` property.

**fsh, the FileSource Shell, is the default**: when no shell is configured and fsh
(`us.bringardner.fsh.ssh.FshShellFactory`) is on the class path, users who log in get fsh. It runs on
Java 11 or later, as parley-ssh does; without fsh, shell requests are refused. `shellFactory=none` turns the
default off, and setting another shell replaces it. `ProcessShellFactory` runs the operating
system's login shell instead.

**fsh works with the access of the account the server runs as**, whoever logged in. Adding fsh to a
server's class path gives every user who can log in a shell (with an access control list, only
users with the "shell" permission): set `shellFactory=none` if they shouldn't have one.

## Not supported

Left out on purpose; none is a common need.

- **X11 forwarding** (`ssh -X` / `-Y`): showing graphical Unix programs from the server on the
  client's screen. The `no-X11-forwarding` option and the certificate extension are understood,
  but X11 requests are refused.
- **Tunnel devices** (`ssh -w`): a VPN through SSH. It needs root and native code to create network
  interfaces, which Java can't do.
- **Using a FIDO security key directly from the client**: talking to a USB key needs native
  libraries. The client can still log in with security keys held by an SSH agent, and the server
  accepts them.
- **WebAuthn security key signatures** (`webauthn-sk-ecdsa-sha2-nistp256@openssh.com`), used only by
  browser-based SSH clients.
- **SFTP version 4-6 extras**: text mode (line ending conversion), ACLs and byte-range locks
  (`BLOCK` / `UNBLOCK`). Text mode is ignored, ACLs are not set or sent, and lock requests are
  answered "unsupported". OpenSSH supports none of these either.

## Build and test

```
mvn verify
```

The tests run the client and server against Apache MINA SSHD, JSch and OpenSSH (test scope only):
OpenSSH's `ssh`, `ssh-keygen` and `ssh-agent` when installed, and private `sshd` instances started on
free ports as the current user. `OpenSshIT` also runs against an OpenSSH server
(`parley.ssh.it.host` / `parley.ssh.it.port`, default localhost) and is skipped when nothing listens
there. Tests that need OpenSSH, Unix or a newer Java are skipped where those are missing.

Not tested here: the Windows agent pipe, Pageant and pseudo terminals on Windows.
