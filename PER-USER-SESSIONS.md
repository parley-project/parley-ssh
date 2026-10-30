# Per-user sessions for parley-ssh: options and what each requires

Status: **tabled, nothing built.** Written 2026-10-30 from a design discussion; no code was changed.

## Requirement

parley-ssh should work like a real ssh server: `ssh -p 2222 tester@host` logs in **as the operating-system
user `tester`**, with that user's uid, groups, home, login shell and files, not as the account the server
runs as.

## Where it stands today

Every session runs as the account the server runs as, whoever logged in (README, "Running operating system
commands is opt-in, and they run as the account the server runs as" and "fsh works with the access of the
account the server runs as"; also the class comments of `ProcessShellFactory` and `ProcessCommandFactory`).

Checked on mx1 (2026-10-30, `tester` logging in with a key): `whoami` prints `parley`, `pwd` prints
`/var/lib/parley` (the service's folder, not `tester`'s home), and files are created owned by `parley`.

What the login name does decide today:

- whether the login is allowed (key in `HOMES/USER/.ssh/authorized_keys`, a password through the access
  control list, or a certificate from a trusted CA);
- the user's SFTP root (the ACL's `userRoot`, else `HOMES/USER`);
- the "shell" permission check on the access control list.

It does **not** change the OS identity of the shell, of programs the shell starts, or of SFTP file access.

Why it cannot simply switch users: the server runs as an unprivileged service user, and the unit file has
`NoNewPrivileges=true`. A process without the right to change uid cannot become another user, and Java has no
`fork`, so the usual "fork, then setuid, then exec" sequence has to be done by a separate program.

## What a real ssh server does (the target)

OpenSSH's order of work, which every option below approximates to some degree:

1. Authenticate the user against the real account (`~/.ssh/authorized_keys` in the real home, with
   `StrictModes` permission checks; passwords through PAM; certificates).
2. Check the account is allowed (`/etc/passwd` entry, locked or expired accounts, `AllowUsers`, `nologin`,
   PAM `account` stage).
3. Make the pty, set its owner to the user and its group to `tty`.
4. In a child process: `pam_open_session`, `initgroups`, `setgid`, `setuid`, `chdir` to the home, set
   `HOME`, `USER`, `LOGNAME`, `SHELL`, `PATH`, `MAIL`, `TERM`, `SSH_CONNECTION`, `SSH_CLIENT`,
   `SSH_TTY`, then `exec` the user's login shell with a leading `-` in `argv[0]` (a login shell).
5. Run sftp, port forwards and agent forwarding as that user too.
6. Close the session: `pam_close_session`, `utmp`/`wtmp`/`lastlog` entries, remove the pty.

The login shell comes from `/etc/passwd` and reads its **own** startup files (`.zprofile`, `.bash_profile`,
`fsh`'s files ...). That also answers "which profile does fsh run": fsh reads fsh's files only for accounts whose
login shell is fsh (`chsh`). A `shellCommand` setting would stay only as an override.

## Parts every option needs

These are the same whichever privilege model is chosen:

| Part | What it takes |
|---|---|
| Real account lookup | Read `/etc/passwd` (uid, gid, home, shell) and group membership. From Java: JNA `getpwnam`/`getgrouplist`, or parse the files. Locked, expired and `nologin` accounts refused. |
| Authentication against real homes | `authorized_keys` read from the user's real `~/.ssh` (opened as that user, or with `StrictModes` checks of owner and mode). The `parley.ssh.homes` test folder goes away (or stays as an option for virtual users). |
| Passwords | PAM (`pam_authenticate`, `pam_acct_mgmt`) through JNA, or keys only. The current access-control-list passwords would not be OS passwords. |
| A session launcher | A small native program: `initgroups`, `setgid`, `setuid`, `chdir`, environment, `exec` of the login shell with a leading `-`. Same family as fsh's `fshexec`; must be built per platform. |
| The pty owned by the user | pty4j makes the pty as the server's uid. For a user's session the slave needs the user as owner and group `tty` (mode 620), done by a privileged part, or the privileged launcher makes the pty itself as sshd does. |
| Environment | `HOME`, `USER`, `LOGNAME`, `SHELL`, `PATH`, `MAIL`, `TERM`, `SSH_*`; the shell's own profile does the rest. |
| SFTP as the user | The in-JVM SFTP code uses the server's uid. It needs a separate process running as the user (like `sftp-server`), or a per-thread uid switch (Linux `setfsuid`/`setfsgid` through JNA, which is fragile and Linux-only). |
| Port forwarding | Listening ports below 1024 as the user, and `AllowTcpForwarding` policy: decide whether it is subject to the account. |
| PAM session | `pam_open_session`/`pam_close_session` for limits, `pam_systemd` (logind session, `XDG_RUNTIME_DIR`), `pam_limits`, `pam_env`, lastlog. |
| Accounting | utmp/wtmp/lastlog (optional but expected). |
| Service unit | Capabilities and sandboxing options to match the chosen option; `NoNewPrivileges=true` conflicts with most of them. |
| Tests | A test host with at least two real accounts, one in an extra group; checks that a session runs as the right uid and groups, cannot read the other's files, and that a restricted account (`nologin`) is refused. |

## Options

### Option 0: Keep the single-account design (and harden it)

The server stays as it is: one service account, the login name only decides who may come in.

- **Requires:** nothing new in code. Document it plainly (already done in the README), keep fsh optional, and
  keep test logins to people who may use the whole service account.
- **Good:** nothing to build; the unprivileged service and `NoNewPrivileges` stay; a compromise of the JVM
  gets only the service account.
- **Bad:** not "a real ssh server". Every user who gets in has the same reach, own files are not
  separated, no per-user groups, home or login shell. Suitable for a test box or a dedicated appliance, not for
  general accounts.
- **Hardening that still helps:** per-user restricted shells (fsh with a command allow list), a chroot-like
  working folder, `ProtectSystem`/`ProtectHome` in the unit file.

### Option A: Run the service as root, with systemd sandboxing

One process does everything and switches uid for each session.

- **Requires:**
  - the unit runs as root (or as a user with ambient `CAP_SETUID`, `CAP_SETGID`, `CAP_CHOWN`,
    `CAP_DAC_READ_SEARCH`, and `CAP_NET_BIND_SERVICE` for port 22; the capability set is root-equivalent
    anyway because `CAP_SETUID` can become uid 0);
  - `NoNewPrivileges=true` removed (or kept, since capabilities already held do not need it; check this on
    the target systemd);
  - the launcher from "Parts every option needs", started by the JVM with privileges, doing
    `initgroups`/`setgid`/`setuid` and dropping all capabilities before `exec`;
  - the pty chown (the JVM has `CAP_CHOWN`);
  - PAM through JNA;
  - sandboxing in the unit: `CapabilityBoundingSet=`, `ProtectSystem=strict`, `PrivateTmp`, `ReadWritePaths`,
    `ProtectKernelTunables` and so on, to shrink what a compromise gets.
- **Good:** the least code of the real options; one process; the JVM's existing pty4j path stays; the
  service can read every user's `authorized_keys` without tricks.
- **Bad:** the JVM that parses untrusted protocol messages is root-equivalent. A bug in the ssh protocol code,
  the SFTP code, or any jar on the class path is a root compromise. Sandboxing limits the damage, not the
  privilege.
- **Effort:** moderate. Launcher, JNA account lookup, PAM, unit changes, tests.

### Option B: Privilege separation (the OpenSSH model)  *(recommended if per-user sessions are wanted)*

Split the server so the code that touches untrusted data has no privilege, and a small program does the one
privileged thing.

- **Requires:**
  - an unprivileged JVM for the protocol, authentication decisions and channel handling;
  - a small **broker** (root or `CAP_SETUID`/`CAP_SETGID`/`CAP_CHOWN`) that the JVM talks to over a Unix
    domain socket, that creates sessions: it takes a user name that the JVM has *already authenticated*,
    verifies it against its own configuration (allowed users, shells), makes the pty, owns the user switch
    (`initgroups`, `setgid`, `setuid`), opens the PAM session, and `exec`s the login shell or `sftp`
    helper, passing the pty master (or pipes) back to the JVM by file-descriptor passing;
  - the broker kept tiny and in a memory-safe or very simple language (C with strict review, or Rust/Go), with
    a fixed protocol: spawn shell, spawn command, spawn sftp, resize, signal, close;
  - a decision on how the broker trusts the JVM: it must not accept "become user X" from a compromised JVM
    unconditionally. Options: the broker re-checks the authentication itself (for example verifies the
    public-key signature, or the key against `authorized_keys`), or it only lets the JVM request users in an
    allow list, accepting that a JVM compromise can then reach those users;
  - the JVM runs as an unprivileged user; the broker runs as root under its own systemd unit
    (`Requires=` the broker socket), with `NoNewPrivileges` on the JVM's unit kept;
  - PAM and the pty live in the broker;
  - a separate `sftp-server`-style helper for SFTP as the user, started by the broker.
- **Good:** a compromise of the JVM no longer means root; the part with privileges is small enough to review;
  matches how OpenSSH is built, so it is explainable to administrators.
- **Bad:** the most work; a native component per platform; a new protocol between the two processes to design
  and test; harder to deploy (two units, a socket, and the broker's policy file).
- **Effort:** large. Broker, protocol, fd passing (pty4j alone cannot do this; use JNA/JNI
  `sendmsg`/`recvmsg` with `SCM_RIGHTS`, fsh already has `socketPair0`/`sendWithDescriptors0` in its native
  layer), PAM, SFTP helper, units, tests including security tests.

### Option C: Delegate the user switch to an existing OS tool

The JVM stays unprivileged and asks an existing program to run the shell as the user: `sudo -n -u USER`,
`su -l USER`, `systemd-run --uid=USER`/`machinectl shell USER@`, or `runuser`.

- **Requires:**
  - a rule that lets the service account run those tools as any (or allowed) user: a `sudoers` entry, or a
    polkit rule for `systemd-run`/`machinectl`;
  - `NoNewPrivileges=true` removed from the unit (it blocks `sudo`/`su` from gaining privilege);
  - the pty made by pty4j still needs the user to own the slave; `su`/`sudo -u` with a pty works as long as the
    tool allocates its own pty (`sudo` with `use_pty`, `su -l` opens `pam_systemd` session): test each;
  - SFTP as the user by running an `sftp-server` command through the same tool.
- **Good:** very little new code; the OS tool already does `initgroups`, PAM and the environment; the JVM
  stays unprivileged.
- **Bad:** the sudoers rule *is* the privilege: allowing the service to run any command as any user is
  root-equivalent again. Narrowing the rule to a fixed wrapper script moves the same trust into the wrapper. Output
  and signals pass through an extra process (Ctrl-C, window size, exit code need testing). Behavior differs
  between distributions and between `sudo`, `su` and `machinectl`. No help on Windows.
- **Effort:** small to medium; security review still needed. Could be a first step toward Option B, with the wrapper
  later replaced by the real broker.

## Comparison

| | Option 0 | A: root + sandbox | B: privilege separation | C: sudo/su/systemd-run |
|---|---|---|---|---|
| Runs as the logged-in user | no | yes | yes | yes |
| Untrusted-input code runs with privilege | no | **yes** | no | no (but the rule is broad) |
| New native component | no | launcher | broker + launcher + sftp helper | none (a wrapper script) |
| PAM / lastlog / logind | no | yes | yes | partly (by the tool) |
| SFTP as the user | no | helper process | helper process | helper through the tool |
| Effort | none | moderate | large | small to medium |
| Closest to OpenSSH | no | partly | yes | partly |

## Other platforms

- **macOS:** same model as Linux (setuid, launchd instead of systemd, Open Directory instead of
  `/etc/passwd`; `getpwnam` still works). Needs a launchd plist that runs the broker as root.
- **Windows:** no `setuid`. A real equivalent needs `LogonUser`/`CreateProcessAsUser` (or `CreateProcessWithLogonW`) from a
  service holding `SeAssignPrimaryTokenPrivilege`, ConPTY for the terminal, and a different account model; treat it as a
  separate project.

## Questions to settle before building

1. Is it acceptable for the first release to support only Linux (and possibly macOS)?
2. Is the goal a general-purpose ssh server on a shared host, or a server for a few trusted accounts? (The
   answer decides between Option A, which is simpler and weaker, and Option B.)
3. Does the server keep its virtual users (the access control list, `userRoot`) next to real accounts, or do real
   accounts replace them? Mixed mode needs a per-user choice of "real account" or "service account".
4. Passwords: PAM, or keys and certificates only?
5. Does fsh become a login shell for real accounts (`chsh`), with the server only running the account's
   shell, or does the server keep a global override?
6. How is the broker (Option B) told which users are allowed, and who may change that list?
7. Port forwarding, agent forwarding and X11: allowed per account?

## Suggested path, if this is taken up again

1. Write the account lookup, `authorized_keys` from real homes, and the `nologin`/locked-account checks (useful
   in every option).
2. Build the launcher and prove it with Option C or Option A on a test host with two accounts.
3. If the server is to face untrusted users, move to Option B: broker, fd-passing protocol, PAM, SFTP helper.
4. Tests: uid, gid and supplementary groups of the session, file ownership of what a session creates, refusal
   of `nologin` accounts, and that the unprivileged JVM cannot ask the broker for a user outside the allowed list.

## Related work already done (for context)

- `81e5fed` in this repo adds `parley.ssh.shellCommand`: a program run as the shell on a real pty
  (pty4j). It runs as the service account today.
- fsh `380ccaa2`: SSH sessions share stdin with programs so queued input is not lost (in-JVM path).
- On mx1 (2026-10-30): `parley.ssh.shellCommand=/opt/fsh/bin/fsh -l` gives job control, vi and less, window
  size and clean no-pty output. Still as the `parley` account.
