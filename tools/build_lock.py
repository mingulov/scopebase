#!/usr/bin/env python3
"""One cooperative build slot per user/host; no command retries or time limits.

The acquired descriptor is inherited by an internal supervisor hop (not by the
command itself), so controller death does not release the slot while the build
still runs, while orphaned grandchildren of the command can never wedge future
builds (observed: stray-probe orphans inheriting the fd held the slot for tens
of minutes past suite exit). Other users/tools and remote guests must coordinate
separately. No process IDs are used for cleanup.
"""

import argparse
import errno
import fcntl
import math
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import sys
import time


class UsageError(Exception):
    pass


class Parser(argparse.ArgumentParser):
    def error(self, message):
        raise UsageError(message)


def directory(path):
    """Create missing components privately and open each without symlinks."""
    if not path.is_absolute() or ".." in path.parts:
        raise UsageError("lock root must be an absolute path without '..'")
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for component in path.parts[1:]:
            try:
                os.mkdir(component, 0o700, dir_fd=fd)
            except FileExistsError:
                pass
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
        info = os.fstat(fd)
        if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077:
            raise UsageError("lock root must be owned by this user and private (0700)")
        return fd
    except BaseException:
        os.close(fd)
        raise


def main(argv=None):
    parser = Parser(description=__doc__)
    parser.add_argument("--lock-root", type=Path)
    parser.add_argument("--resource", default="build")
    parser.add_argument("--timeout", type=float)
    parser.add_argument("--supervise-internal", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    root_fd = lock_fd = None
    try:
        args = parser.parse_args(argv)
        if not args.command or args.command[0] != "--" or len(args.command) < 2:
            raise UsageError("expected -- COMMAND ARG...")
        if args.supervise_internal:
            # Lease hop: the inherited lock fd stays open in THIS process
            # (never closed, never passed on — close_fds keeps it from the
            # command), so the slot survives controller death exactly as the
            # killed-controller test requires, while the command's orphans
            # hold nothing and cannot wedge later builds.
            # L135: the lease holds until the command actually exits,
            # including signal paths. SIGINT is ignored (the command gets
            # it from the terminal itself when grouped; a directed INT
            # must not release early). SIGTERM/SIGHUP forward to the
            # command while the supervisor keeps waiting (killability
            # without early release). The child restores exactly what
            # the supervisor inherited (plain variables — no allocation
            # between fork and exec), so an ignored disposition never
            # leaks past exec into the command (SIG_IGN survives exec
            # and would neuter e.g. a self-TERM suicide).
            # L137: no ignore window across spawn — a TERM/HUP landing
            # during Popen is stashed, then drained right after the
            # forward handlers install (a signal in the swap lands in
            # exactly one of stash/forward — never discarded, never
            # doubled). Delivery races the command's own trap install
            # by nature — the contract is delivery (death or trap),
            # never discard. Only a pre-install death (no command
            # exists yet — nothing to protect) can release early.
            sigint_saved = signal.getsignal(signal.SIGINT)
            sigterm_saved = signal.getsignal(signal.SIGTERM)
            sighup_saved = signal.getsignal(signal.SIGHUP)
            pending = []

            def _stash(signum, _frame):
                pending.append(signum)

            signal.signal(signal.SIGINT, signal.SIG_IGN)
            signal.signal(signal.SIGTERM, _stash)
            signal.signal(signal.SIGHUP, _stash)

            def _restore():
                signal.signal(signal.SIGINT, sigint_saved)
                signal.signal(signal.SIGTERM, sigterm_saved)
                signal.signal(signal.SIGHUP, sighup_saved)

            child = subprocess.Popen(args.command[1:], preexec_fn=_restore)

            def _forward(signum, _frame):
                try:
                    child.send_signal(signum)
                except ProcessLookupError:
                    pass

            signal.signal(signal.SIGTERM, _forward)
            signal.signal(signal.SIGHUP, _forward)
            for signum in pending:
                _forward(signum, None)
            code = child.wait()
            return code if code >= 0 else 128 - code
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", args.resource, flags=re.ASCII):
            raise UsageError("resource must be an ASCII basename of 1 to 64 characters")
        if args.timeout is not None and (not math.isfinite(args.timeout) or args.timeout < 0):
            raise UsageError("timeout must be a finite nonnegative number")
        if args.lock_root is None:
            runtime = os.environ.get("XDG_RUNTIME_DIR")
            args.lock_root = (Path(runtime) / "scopebase-locks" if runtime
                              else Path.home() / ".cache/scopebase/locks")
        root_fd = directory(args.lock_root)
        lock_fd = os.open(args.resource + ".lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW,
                          0o600, dir_fd=root_fd)
        os.close(root_fd)
        root_fd = None
        # L136: the lock must never sit on fd 0/1/2 (a wrapper started
        # with stdio closed would otherwise hand the command the slot
        # as a standard stream — close_fds preserves those — and an
        # orphan keeping stdio would wedge later builds).
        moved = fcntl.fcntl(lock_fd, fcntl.F_DUPFD_CLOEXEC, 3)
        os.close(lock_fd)
        lock_fd = moved
        info = os.fstat(lock_fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise UsageError("lock file must be a private regular file owned by this user")
        deadline = None if args.timeout is None else time.monotonic() + args.timeout
        while True:
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if deadline is not None:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        print("scopebase-build: lock acquisition timed out; command not launched", file=sys.stderr)
                        return 75
                    time.sleep(min(0.02, remaining))
                else:
                    time.sleep(0.02)
        # Launch lives outside the acquisition loop: child status 75 never retries.
        # The fd goes to the supervisor hop only — never to the command
        # (orphaned command descendants must not inherit the slot).
        supervisor = [sys.executable, os.path.realpath(__file__),
                      "--supervise-internal", "--", *args.command[1:]]
        child = subprocess.Popen(supervisor, pass_fds=(lock_fd,))
        code = child.wait()
        return code if code >= 0 else 128 - code
    except UsageError as error:
        print("scopebase-build: " + str(error), file=sys.stderr)
        return 64
    except KeyboardInterrupt:
        return 130
    except OSError as error:
        print("scopebase-build: " + str(error), file=sys.stderr)
        if error.errno == errno.ENOENT and lock_fd is not None:
            return 127
        if error.errno == errno.EACCES and lock_fd is not None:
            return 126
        return 64
    finally:
        if lock_fd is not None:
            os.close(lock_fd)
        if root_fd is not None:
            os.close(root_fd)


if __name__ == "__main__":
    sys.exit(main())
