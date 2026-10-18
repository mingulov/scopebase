#!/usr/bin/env python3
"""One cooperative build slot per user/host; no command retries or time limits.

The acquired descriptor is inherited by the direct child, so controller death
does not release the slot while that child still owns it. Other users/tools and
remote guests must coordinate separately. No process IDs are used for cleanup.
"""

import argparse
import errno
import fcntl
import math
import os
from pathlib import Path
import re
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
    parser.add_argument("command", nargs=argparse.REMAINDER)
    root_fd = lock_fd = None
    try:
        args = parser.parse_args(argv)
        if not args.command or args.command[0] != "--" or len(args.command) < 2:
            raise UsageError("expected -- COMMAND ARG...")
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
        child = subprocess.Popen(args.command[1:], pass_fds=(lock_fd,))
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
