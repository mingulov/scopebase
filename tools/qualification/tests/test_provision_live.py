"""Live privileged mount tests for provision_fs (TT04_LIVE_MOUNTS=1).

These tests bind, observe, and unmount REAL filesystem objects
with sudo: they prove the owned-bind gate against genuine
mountinfo semantics (filesystem source, subtree root, covered
object identity) and prove the churn driver bind/restore cycle
and the traversal mount guard against a live mount. Everything
is strictly cleaned up (umount, driver quit/kill, rmtree) in
finally blocks; each test skips unless TT04_LIVE_MOUNTS=1 and
passwordless sudo mount/umount works.

S17-round5: every mount effect and every observation through a
live mount runs inside the keeper mount namespace (rprivate):
the kernel rejects MS_MOVE under shared ancestors, so the
reversible move-verify-detach retirement only works on a
private chain, and confinement keeps the host table clean.
LiveBindTests.setUp ensures the ns; sudo() then enters it for
every call (mount-indifferent commands — losetup, chown,
kill — behave identically inside), and reads/writes through
a live mount go through the ns_* helpers. Direct reads stay
only where no mount is live at that path at that moment.
"""

import contextlib
import json
import os
import pwd
import resource
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import provision_fs as provision  # noqa: E402


def live_mounts_enabled():
    if os.environ.get("TT04_LIVE_MOUNTS") != "1":
        return False
    try:
        probes = [
            ["sudo", "-n", "true"],
            # S17-round5: confinement needs the namespace
            # tools through the same sudo path that uses
            # them (they may be absent from the user PATH
            # while present in sudo's secure_path).
            ["sudo", "-n", "unshare", "--version"],
            ["sudo", "-n", "nsenter", "--version"],
        ]
        for argv in probes:
            proc = subprocess.run(
                argv, capture_output=True, timeout=30)
            if proc.returncode != 0:
                return False
    except OSError:
        return False
    return True


def sudo(*argv, timeout=60, input=None):
    # S17-round5: once LiveBindTests.setUp ensures the keeper
    # ns, every sudo call enters it — mounts land on the
    # private chain move-verify-detach needs, and reads see
    # the mounts under test. Mount-indifferent commands
    # (losetup/chown/kill) behave identically inside (global
    # devices, same filesystem, same pid namespace).
    ns = provision._ns_active()
    prefix = (["sudo", "-n", "nsenter", f"--mount={ns}"]
              if ns is not None else ["sudo", "-n"])
    return subprocess.run(prefix + list(argv), capture_output=True,
                          text=True, timeout=timeout, input=input)


def live_ns():
    """The ensured keeper ns path, or a loud failure."""
    ns = provision._ns_active()
    if ns is None:
        raise AssertionError(
            "live mount ns not ensured (setUp must ensure)")
    return ns


def ns_text(path):
    """Read text THROUGH a live mount (inside the ns)."""
    seen = sudo("cat", path)
    if seen.returncode != 0:
        raise AssertionError(
            f"ns read of {path} failed: {seen.stderr}")
    return seen.stdout


def ns_exists(path):
    """Existence THROUGH a live mount (inside the ns)."""
    return sudo("test", "-e", path).returncode == 0


def ns_write_user(path, data):
    """Write text THROUGH a live mount as the calling user.

    S17-round5: runuser (same util-linux package as the
    nsenter this suite already requires) drops back to the
    controller identity inside the ns, so folded-ownership
    proofs keep their unprivileged writer.
    """
    user = pwd.getpwuid(os.geteuid()).pw_name
    done = sudo("runuser", "-u", user, "--", "tee", path,
                input=data)
    if done.returncode != 0 or done.stdout != data:
        raise AssertionError(
            f"ns user-write to {path} failed: "
            f"rc={done.returncode} err={done.stderr!r}")


def mount_live_at(target):
    """Live-table rows at target (in-ns once ensured)."""
    return provision.find_mounts(
        provision.read_mount_table(), target)


def retire_verified_mount(target, verified_mnt_id):
    """Best-effort umount of verified identity at target.

    S93-round5: a privileged test retires its mount on every
    post-effect failure — but only verified identity. Whatever
    is live at the test's own target must be the mount it
    verified (or nothing was verified yet — then whatever the
    helper left there). A foreign replacement is left alone,
    loudly visible, instead of unmounted. An unreadable table
    still attempts the umount (best effort: umount of a
    non-mount fails harmlessly). Returns True when the umount
    was attempted.
    """
    try:
        live = mount_live_at(target)
    except Exception:
        live = None
    if live is None or (live and (
            verified_mnt_id is None or
            live[0]["mnt_id"] == verified_mnt_id)):
        sudo("umount", target)
        return True
    return False


def signal_verified_proc(victim, signum):
    """Re-pin, re-verify, and signal one owned proc. (S92)

    Fresh pidfd pin plus fresh starttime, then the
    identity-verified signal_owned path (pidfd-bound signal,
    privileged-helper escalation on EPERM — no numeric kill at
    any stage). Returns True when a signal was sent, False when
    the process was already gone. ProcAbsent/ProcUnknown
    propagate (nothing signaled); AdmissionError propagates
    when identity cannot be verified. The fresh pin always
    closes — including on the error paths.
    """
    pin = provision.pin_proc(victim)
    try:
        _, start = provision.stat_state_start(victim)
        return provision.signal_owned(victim, signum, pin, start)
    finally:
        os.close(pin)


def kill_bound_keeper(pid, expected_start):
    """SIGKILL one keeper life through PIDFD authority. (S116)

    A fresh pidfd pin plus signal_owned against the ORIGINALLY
    verified starttime (the caller's retained
    _MOUNT_NS_IDENTITY anchor — never a re-read number): exit
    and PID reuse before dispatch refuse (AdmissionError)
    instead of redirecting a root-authorized signal, and the
    EPERM escalation re-pins and re-verifies the same original
    starttime inside the helper. Returns True when the signal
    was sent, False when the life was already gone. The pin
    always closes. No numeric kill at any stage.
    """
    import signal as _signal
    pin = provision.pin_proc(pid)
    try:
        return provision.signal_owned(
            pid, _signal.SIGKILL, pin, expected_start)
    finally:
        os.close(pin)


@contextlib.contextmanager
def private_keeper_state(tmpdir):
    """Redirect keeper records to tmpdir; exclusive ownership. (S117)

    Patches provision._keeper_paths to a private pidfile/candir
    pair under tmpdir (the lock, publish tmp, and evidence
    paths all derive from it) and drops the cached keeper —
    no in-memory identity crosses the boundary in either
    direction, so callers ensure a private keeper inside,
    retire it inside, and re-ensure (fully re-verifying) the
    shared keeper after. Restoration is exact on every path,
    including mid-test failure. Subprocess entries are NOT
    redirected (separate address space): they keep consulting
    the shared paths unless a test redirects chosen
    subprocesses explicitly (write_redirected_tool plus
    private_keeper_subprocess_env, S137); anything still on
    the shared paths requires them alive and byte-identical.
    """
    pidfile = os.path.join(tmpdir, "private-keeper.pid")
    candir = os.path.join(tmpdir, "private-keeper-canary")
    saved_paths = provision._keeper_paths
    provision._keeper_paths = lambda: (pidfile, candir)
    provision._MOUNT_NS = None
    provision._MOUNT_NS_IDENTITY = None
    try:
        yield (pidfile, candir)
    finally:
        provision._keeper_paths = saved_paths
        provision._MOUNT_NS = None
        provision._MOUNT_NS_IDENTITY = None


def poll_proc_gone(pid, timeout=15):
    """True when /proc/<pid> vanishes within timeout. (S117)

    R10-008: only ENOENT counts as gone — an entry that
    cannot be stated (EACCES: alive but unobservable, e.g.
    hidepid) answers present, routing to the survivor /
    unproven branch instead of counting as retirement.
    R12-009: hidepid=2 returns ENOENT for hidden LIVE tasks,
    so ENOENT alone proves nothing — only kill-ESRCH (the
    R11-001 primitive: kill bypasses /proc visibility)
    proves death; anything else answers present.
    """
    def missing():
        try:
            os.stat(f"/proc/{pid}")
        except FileNotFoundError:
            return provision._pid_proven_dead(pid)
        except OSError:
            return False
        return False

    deadline = time.time() + timeout
    while time.time() < deadline:
        if missing():
            return True
        time.sleep(0.2)
    return missing()


def register_keeper_life(lives):
    """Register the CURRENTLY ensured keeper life. (S131)

    Appends (pid, starttime) from the in-process ensured
    identity to `lives` and returns it. Call IMMEDIATELY after
    ensure_mount_ns — before every fallible observation (pidfile
    reads, table reads, assertions) — so a failure between
    acquisition and observation still reaches the finalizer
    instead of escaping it with a live keeper. Refuses loudly
    when no keeper is ensured.
    """
    identity = provision._MOUNT_NS_IDENTITY
    if identity is None:
        raise AssertionError(
            "no ensured keeper identity to register "
            "(ensure first, then register immediately)")
    pid, _, start, _ = identity
    lives.append((pid, start))
    return (pid, start)


# R12-010: entry snapshot unreadable — distinct from None
# (never existed). An unreadable entry never proves
# nothingness: adoption retains on it whatever the final
# read shows.
_ENTRY_SNAPSHOT_UNREADABLE = object()


def snapshot_entry_record(pidfile):
    """Pre-entry record snapshot for adoption comparison. (R12-010)

    Record bytes when readable; None when the record never
    existed (FileNotFoundError); _ENTRY_SNAPSHOT_UNREADABLE
    on any other read error (denial, I/O failure — never
    collapsed into None, which would let entry+final read
    failures around an erroneous spawn discharge custody).
    """
    try:
        with open(pidfile, "rb") as handle:
            return handle.read()
    except FileNotFoundError:
        return None
    except OSError:
        return _ENTRY_SNAPSHOT_UNREADABLE


def resolve_limit_setup(specified_soft, specified_hard,
                        inherited_hard, require_infinity):
    """R15-009: adaptive rlimit setup decision (pure — no syscalls).

    The soft-limit cases and the IR-006 pin used to call
    setrlimit((., inf)) unconditionally; under a viable finite
    inherited hard limit the raise is forbidden (ValueError),
    the middleman exited nonzero in setup, and the tests FAILED
    in an environment R14-013 explicitly supports. Setup now
    adapts: try the specified pair, fall back to
    (finite-soft, inherited-hard) when infinity is unraisable
    (same soft-clamp path, same assertions), and skip explicitly
    when the case budget exceeds hard or infinity is required
    but unavailable (the pin).

    Only the inherited HARD gates applicability: raising soft
    within hard is permitted, so the inherited soft is not an
    input. Returns ("apply", (soft, hard)) or ("skip", reason).
    The middleman reports skips through the queue with exit 0;
    the parent skips explicitly.
    """
    inf = resource.RLIM_INFINITY

    def effective(value):
        return float("inf") if value == inf else value

    if effective(specified_soft) > effective(specified_hard):
        raise AssertionError(
            "invalid specified pair: soft %r exceeds hard %r"
            % (specified_soft, specified_hard))
    if require_infinity and effective(inherited_hard) != float("inf"):
        return ("skip",
                "infinity required but inherited hard is finite (%r)"
                % (inherited_hard,))
    # Specified applicable as-is when it raises nothing above
    # the inherited hard.
    if effective(specified_hard) <= effective(inherited_hard):
        return ("apply", (specified_soft, specified_hard))
    # Infinity (or a finite raise) is unraisable: fall back to
    # (finite-soft, inherited-hard) — same soft-clamp path.
    if effective(specified_soft) > effective(inherited_hard):
        return ("skip",
                "case budget %r exceeds inherited hard %r"
                % (specified_soft, inherited_hard))
    return ("apply", (specified_soft, inherited_hard))


def run_bounded_reader_case(reader, timeout=10):
    """Run a record reader in a reaped child process. (R12-013)

    Returns (finished, payload, exitcode): ``finished`` True
    carries the reader's return as ``payload`` with a clean
    (0) exit; a raised reader returns
    (False, ("raised", repr), exitcode) with the child exited
    cleanly after reporting; anything else — bound lapse
    (SIGKILL-terminated, escalated from SIGTERM), child
    crash, a missing payload — returns (False, None,
    exitcode) with the child reaped.
    Independently enforceable termination: threads cannot
    be killed, so a restored unbounded read (FIFO block,
    /dev/zero alloc) in a daemon thread would wedge or OOM
    the shared interpreter past the assertion; a child
    process is killed and its address space freed.
    R13-011: the child also runs under a memory budget
    (RLIMIT_AS = parent VmSize + 512MiB, floored at 2GiB
    when unreadable): an unbounded allocator raises
    MemoryError in-child and reports it instead of
    exhausting shared runner memory toward an OOM kill
    (whose signal exit previously passed as "contained").
    R14-013: the effective budget is min(computed, inherited
    soft, inherited hard) — the child never raises an
    inherited limit (an unprivileged hard-raise fails, and a
    soft-raise would defeat the environment's tighter
    budget).
    Fork context (closures need no pickling; spawn would
    refuse them) with pre-fork stdio flush (no double
    flush into redirected suite logs). Payloads must be
    picklable across the result pipe.
    """
    import multiprocessing as _mp
    import sys as _sys
    _sys.stdout.flush()
    _sys.stderr.flush()
    ctx = _mp.get_context("fork")
    recv_conn, send_conn = ctx.Pipe(duplex=False)
    # R13-011: worker address-space budget (see docstring).
    # resource is imported at module top (no post-fork import:
    # the import lock may be held across the fork).
    budget = 2 * 1024 * 1024 * 1024
    try:
        with open("/proc/self/status") as handle:
            for line in handle:
                if line.startswith("VmSize:"):
                    current_kb = int(line.split()[1])
                    budget = (current_kb // 1024 + 512) * 1024 * 1024
                    break
    except OSError:
        pass

    def _target(conn, func, cap):
        if cap is not None:
            try:
                # R14-013: respect inherited limits — an
                # unprivileged child cannot raise the hard limit
                # (a forbidden increase reports budget-unset and
                # the reader never runs), and a tighter inherited
                # soft limit is the environment's budget (raising
                # it would weaken containment). Infinite bounds
                # do not constrain, on either representation —
                # IR-006: RLIM_INFINITY is -1 here (probed:
                # Python 3.14, Linux), so the >= 0 filters skip
                # it (a bare min would sink the finite computed
                # cap to -1 = unlimited); a huge-positive
                # infinity loses min() against the finite cap.
                # Both lines are load-bearing — neither the
                # filters nor the min() may go.
                soft, hard = resource.getrlimit(resource.RLIMIT_AS)
                if hard >= 0:
                    cap = min(cap, hard)
                if soft >= 0:
                    cap = min(cap, soft)
                resource.setrlimit(
                    resource.RLIMIT_AS, (cap, cap))
            except Exception as exc:
                conn.send(("raised", "budget-unset:%r" % (exc,)))
                conn.close()
                return
        try:
            conn.send(("ok", func()))
        except BaseException as exc:
            conn.send(("raised", repr(exc)))
        finally:
            conn.close()

    proc = ctx.Process(
        target=_target, args=(send_conn, reader, budget))
    proc.start()
    send_conn.close()
    proc.join(timeout)
    if proc.is_alive():
        proc.terminate()
        proc.join(5)
        if proc.is_alive():
            proc.kill()
            proc.join(5)
        recv_conn.close()
        proc.join()
        return (False, None, proc.exitcode)
    exitcode = proc.exitcode
    try:
        if not recv_conn.poll(10):
            kind, payload = ("missing", None)
        else:
            kind, payload = recv_conn.recv()
    except EOFError:
        kind, payload = ("missing", None)
    finally:
        recv_conn.close()
    if exitcode != 0 or kind != "ok":
        if kind == "raised":
            _sys.stderr.write(
                "bounded reader raised in child: %s\n"
                % (payload,))
            # R13-011: the raised repr rides the payload slot so
            # callers can require the budget-fired MemoryError
            # (a timeout/OOM signal death arrives payload-less).
            return (False, ("raised", payload), exitcode)
        return (False, None, exitcode)
    return (True, payload, exitcode)


def userns_unshare_available():
    """True when unprivileged `unshare -rm` works. (R12-012)

    Tool presence (shutil.which) does not establish
    capability: sysctl, LSM, or container policy may deny
    user-namespace creation while the binary sits installed.
    Probe with a trivial `unshare -rm true` (no namespaces
    escape: true exits at once).
    """
    unshare = shutil.which("unshare")
    if not unshare:
        return False
    try:
        probe = subprocess.run(
            [unshare, "-rm", "true"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, timeout=30)
    except (OSError, subprocess.SubprocessError):
        return False
    return probe.returncode == 0


def spawn_real_mountns_sleeper():
    """Spawn sleep under unprivileged unshare -rm. (R12-012)

    Raises unittest.SkipTest with an explicit capability
    message when user namespaces are unavailable (tool
    present but creation denied) — ordinary discovery must
    report the missing capability, never run into a dead-
    child readlink raise or a never-left-namespace failure.
    Caller owns cleanup (kill+wait).
    """
    if not userns_unshare_available():
        raise unittest.SkipTest(
            "needs unprivileged user namespaces "
            "(unshare -rm refused)")
    return subprocess.Popen(
        ["unshare", "-rm", "sleep", "120"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def adopt_recorded_replacement(pidfile, stale, lives):
    """Adopt an erroneously spawned replacement into lives (R10-009).

    Fixtured entries must never spawn; when one does, it
    replaces the private record, orphaning the new pid from
    ``lives``. Compare the record against the pre-entry
    snapshot ``stale``: an unchanged record, or a record
    that never existed (``stale`` None), means nothing to
    adopt (False). A changed record flags the fixture
    retained (True) and, when the recorded pid is
    identifiable and provably alive, appends its
    (pid, current-starttime) binding so the finalizer kills
    the verified replacement instead of leaking it.
    Malformed, dead, or unreadable replacements adopt
    nothing — the record alone is retained for manual
    recovery. R11-007: neither does a holder outside the
    RECORDED mount namespace — adoption samples whoever
    holds the number now, so without the namespace binding
    a recycled replacement would grant quiescence authority
    over a stranger (its sampled starttime verifies BY
    CONSTRUCTION, and the kill lands). The gate is one
    unprivileged readlink; the canary is deliberately NOT
    rechecked (mount-secret proof needs nsenter privilege —
    entering our private mountns already requires it, so a
    namespace match with a live holder is the binding that
    matters here). In particular an unreadable-or-gone record
    after a record existed at entry (R11-008) flags retained
    (True): silent False would let teardown erase the
    recovery state of a replacement the finalizer never saw.
    R12-010: ``stale`` may be _ENTRY_SNAPSHOT_UNREADABLE (the
    entry read itself failed) — the ``is not None`` arms below
    retain on it whatever the final read shows, since entry
    failure never proves never-existed.
    The read itself is production's S28 bounded reader
    (R11-009): O_NONBLOCK open, same-descriptor regular-file
    check, 1 MiB cap — a FIFO or device at the pidfile
    refuses instead of hanging the finalizer before
    quiescence or retention. Symlinks resolve at open (S28
    semantics): a link to a regular record reads the same
    bounded bytes. Never raises.
    """
    try:
        current, _ = provision.read_regular_capped(pidfile)
    except (OSError, provision.AdmissionError):
        return stale is not None
    if current == stale:
        return False
    state = provision._parse_keeper_state(current)
    if state is None:
        return True
    pid, nsid, _canary = state
    try:
        bound = provision._keeper_starttime(pid)
    except Exception:
        return True
    if bound is None:
        return True
    # R11-007: the sampled life must still run the RECORDED
    # mount namespace — else this number was recycled to a
    # stranger since the record was published, and adopting
    # (pid, sampled-start) would aim quiescence at it (the
    # sample verifies by construction). Unreadable ns link
    # refuses the same way. Either way the record stays
    # retained (True) for manual recovery.
    try:
        link = os.readlink(f"/proc/{pid}/ns/mnt")
    except OSError:
        return True
    if link != f"mnt:[{nsid}]":
        return True
    lives.append((pid, bound))
    return True


def quiesce_private_lives(lives, timeout=15):
    """Best-effort retire of owned private keeper lives. (S117)

    `lives` holds (pid, starttime) pairs this test exclusively
    owns (recorded at ensure time via register_keeper_life).
    Each number is signaled ONLY while it still hosts the
    recorded life — a dead or recycled number is left alone,
    never killed by number. A signaled life is re-checked
    (gone within `timeout`) before it counts as retired.
    Never raises. Returns the lives whose retirement is
    UNPROVEN as [(pid, starttime, reason)] — a kill fault, a
    survivor, or unreadable state; callers retain the private
    records/dirs and fail loudly on a non-empty return
    instead of warning-and-passing over a live keeper (S131).
    """
    unproven = []
    for pid, start in lives:
        try:
            current = provision._keeper_starttime(pid)
        except Exception as exc:
            sys.stderr.write(
                "WARNING: private keeper life pid=%d start=%r "
                "state unreadable: %r; retirement unproven, "
                "retire by hand\n" % (pid, start, exc))
            unproven.append(
                (pid, start, f"starttime unreadable: {exc!r}"))
            continue
        if current is None:
            # R11-006: None is unknown (gone, unreadable, or
            # malformed — S100), never verified-foreign. The
            # hardened poll splits it: ENOENT-gone retires
            # silently; present-but-unobservable answers
            # unproven (S131 — callers retain + fail loud),
            # never silent discharge. timeout=0: a single
            # presence probe — this life was never signaled,
            # so no death wait is owed.
            if poll_proc_gone(pid, timeout=0):
                continue
            sys.stderr.write(
                "WARNING: private keeper life pid=%d start=%r "
                "starttime unreadable but present; retirement "
                "unproven, retire by hand\n" % (pid, start))
            unproven.append(
                (pid, start,
                 "starttime unreadable but present; retire by hand"))
            continue
        if current != start:
            continue
        try:
            sent = kill_bound_keeper(pid, start)
        except provision.ProcAbsent:
            # R10-014: gone between the starttime check and the
            # pin — proven absence (pidfd_open ESRCH: the number
            # hosts nothing, so the observed life is dead),
            # retired without signaling. ProcUnknown and
            # AdmissionError stay below: unproven, never retired.
            continue
        except Exception as exc:
            sys.stderr.write(
                "WARNING: private keeper life pid=%d start=%r "
                "not proven retired: %r; retire by hand\n"
                % (pid, start, exc))
            unproven.append(
                (pid, start, f"kill failed: {exc!r}"))
            continue
        if not sent:
            # Gone between the starttime check and the
            # signal: retired, not unproven.
            continue
        if poll_proc_gone(pid, timeout=timeout):
            continue
        sys.stderr.write(
            "WARNING: private keeper life pid=%d start=%r "
            "survived SIGKILL; retirement unproven, retire "
            "by hand\n" % (pid, start))
        unproven.append(
            (pid, start, "survived SIGKILL; retire by hand"))
    return unproven


# Env channels that redirect ONE entry subprocess's keeper
# paths to private (stale/absent) state. Only
# write_redirected_tool honors them; production and plain
# `python provision_fs.py ...` invocations never read them.
PRIVATE_KEEPER_PIDFILE_ENV = "SCOPEBASE_TEST_KEEPER_PIDFILE"
PRIVATE_KEEPER_CANDIR_ENV = "SCOPEBASE_TEST_KEEPER_CANDIR"


def write_redirected_tool(tmpdir):
    """An entry script honoring the private-keeper env. (S137)

    Writes tmpdir/redirected-tool.py, which imports
    provision_fs from the suite's own qualdir, patches ITS
    _keeper_paths to the env-supplied private pair (when both
    are set), then dispatches provision.main() — so the entry
    subprocess consults stale/absent private keeper state
    while the shared keeper stays alive and byte-identical.
    Two test-only probes: --probe-keeper-paths prints the
    effective (pidfile, candir) as JSON; --probe-ensure
    prints ENSURED <nspath> or REFUSED <error> (rc 0 either
    way). Returns the script path.
    """
    qualdir = os.path.dirname(provision.__file__)
    script = os.path.join(tmpdir, "redirected-tool.py")
    with open(script, "w") as handle:
        handle.write(
            "import json, os, sys\n"
            f"sys.path.insert(0, {qualdir!r})\n"
            "import provision_fs as provision\n"
            f"pidfile = os.environ.get("
            f"{PRIVATE_KEEPER_PIDFILE_ENV!r})\n"
            f"candir = os.environ.get("
            f"{PRIVATE_KEEPER_CANDIR_ENV!r})\n"
            "if pidfile and candir:\n"
            "    provision._keeper_paths = "
            "lambda: (pidfile, candir)\n"
            "if sys.argv[1:2] == ['--probe-keeper-paths']:\n"
            "    print(json.dumps(provision._keeper_paths()))\n"
            "    sys.exit(0)\n"
            "if sys.argv[1:2] == ['--probe-ensure']:\n"
            "    try:\n"
            "        nspath = provision.ensure_mount_ns()\n"
            "    except Exception as exc:\n"
            "        print(f'REFUSED {exc}')\n"
            "    else:\n"
            "        print(f'ENSURED {nspath}')\n"
            "    sys.exit(0)\n"
            "sys.exit(provision.main())\n")
    return script


def private_keeper_subprocess_env(pidfile, candir):
    """Env redirecting a subprocess's keeper paths. (S137)

    Copies os.environ with the private pair set, for subprocess
    invocations of write_redirected_tool output. The shared
    keeper paths stay untouched — S117's constraint stands.
    """
    env = dict(os.environ)
    env[PRIVATE_KEEPER_PIDFILE_ENV] = pidfile
    env[PRIVATE_KEEPER_CANDIR_ENV] = candir
    return env


def ext4_arm_verdict(ext4_present, have_loop, have_mkfs):
    """E2E ext4-arm obligation. (G1-I3)

    Returns "verified" when the arm ran, "required" when the arm
    is missing on a loop+mkfs-capable host (the caller must
    fail, never pass), else "skipped" (the caller checks the
    FS01 skip reason instead).
    """
    if ext4_present:
        return "verified"
    if have_loop and have_mkfs:
        return "required"
    return "skipped"


def fs01_skip_reason_ok(reason):
    """True only for IDENTIFIED capability unavailability. (S113)

    Production's FS01 skip reasons name one of three identified
    unavailability outcomes: the absent formatter tool
    ("missing mkfs.ext4 tool") or a native loop-attach refusal
    ("loop-control not openable", "no free loop device" — the
    attach failures arrive wrapped in production's "losetup
    refused" report line, so the wrapper is accepted only with
    an identified inner cause). Everything else is NOT a
    capability skip: formatter failures ("mkfs.ext4 refused" —
    before loop custody is armed), bare utility failures
    ("losetup refused" without an identified cause; production
    attaches via native ioctls, so a utility failure proves
    nothing), uncertain outcomes ("losetup outcome uncertain"
    — unresolved custody, never a clean skip),
    association/integrity refusals, loop configure failures,
    mount-stage failures (which imply loop worked), and
    empty/unrelated text.
    """
    text = (reason or "").lower()
    if not text:
        return False
    return any(marker in text for marker in (
        "missing mkfs.ext4 tool",
        "loop-control not openable",
        "no free loop device",
    ))


# S113: the exact capability production uses — LOOP_CTL_GET_FREE
# on /dev/loop-control (provision._configure_free_loop), never
# the losetup CLI. Runs under sudo (the capability's real user
# is the privileged helper); prints LOOP_VIABLE plus the free
# number, and dies (nonzero, no marker) on any refusal.
NATIVE_LOOP_PROBE = (
    "import fcntl, os\n"
    "fd = os.open('/dev/loop-control', os.O_RDWR)\n"
    "try:\n"
    f"    num = fcntl.ioctl(fd, {provision.LOOP_CTL_GET_FREE})\n"
    "finally:\n"
    "    os.close(fd)\n"
    "print('LOOP_VIABLE', num)\n"
)


def native_loop_probe_verdict(returncode, stdout):
    """True only when the native probe proves viability. (S113)

    Any other outcome — nonzero exit, missing marker, absent
    output — degrades to not-viable: the E2E then takes the
    skip path, where the FS01 reason must still name a real
    missing capability (fail closed, never a forced pass or a
    forced failure from an inconclusive probe).
    """
    if returncode != 0:
        return False
    return "LOOP_VIABLE" in (stdout or "")


def fixture_root_gone(run):
    """True only when the fixture root is proven absent. (R11-010)

    ``os.path.exists`` swallows every OSError into False, so an
    unstatable-but-surviving root (EACCES, I/O failure) would
    read as removed and disable preservation. Only ENOENT
    counts as gone; any other stat failure reports surviving
    (False) — unobservable is not removed. Follows symlinks,
    exactly like the prior exists() (residual, first noted
    under a misnumbered R11-007 entry: no in-system producer
    symlinks a fixture root). Never raises.
    """
    try:
        os.stat(run)
    except FileNotFoundError:
        return True
    except OSError:
        return False
    return False


def e2e_retirement_verdict(cleanup_ok, leftovers, host_clean,
                           root_gone):
    """'retired' only when cleanup worked with no residue. (S118)

    `leftovers` is the list of live rows still under the
    fixture root (None when unobservable); `host_clean` tells
    whether the host table shows no fixture residue;
    `root_gone` tells whether the fixture root itself was
    removed (R10-010: a standing root is residue — the
    false-cleanup-success path must preserve, never retire).
    Any failed cleanup, any leftover row, any host residue, a
    surviving root, or any unobservable residue returns
    'preserve' — unknown is not retired.
    """
    if (cleanup_ok and leftovers == [] and host_clean
            and root_gone):
        return "retired"
    return "preserve"


def e2e_retirement_retains_tmp(verdict):
    """True unless retirement is proven. (S130)

    The ORIGINAL fixture tmpdir survives exactly when the
    e2e_retirement_verdict is not "retired" — automatic
    removal is conditional on proven retirement, since
    copies alone (new inodes, original paths in the
    manifest) cannot recover the fixture.
    """
    return verdict != "retired"


def remove_tmp_unless_retained(tmp, retain):
    """rmtree a fixture tmpdir unless retained. (S130)

    When `retain` is true the ORIGINAL directory is kept
    loudly for manual recovery (same inodes the manifest
    names) and False is returned; otherwise the tmpdir is
    removed and True is returned. Never raises.
    """
    if retain:
        sys.stderr.write(
            f"RETAINED original fixture tmpdir {tmp} for "
            f"manual recovery (retirement unproven; the "
            f"manifest names original paths/identities)\n")
        return False
    shutil.rmtree(tmp, ignore_errors=True)
    return True


def preserve_e2e_evidence(run, manifest, detail):
    """Copy manifest + fixture root aside; return the dir. (S118)

    On failed or uncertain retirement the evidence must live
    OUTSIDE the fixture tmpdir (copies have new inodes, so
    the ORIGINAL tmpdir is additionally retained via
    remove_tmp_unless_retained — S130); the REASON note
    records the original run/manifest identities so recovery
    can verify it holds the same objects the manifest names.
    Best effort and never raises (a preservation fault must
    not mask the retirement fault it records); always reports
    loudly to stderr, including the destination directory for
    manual recovery.
    """
    dest = tempfile.mkdtemp(prefix="provision-e2e-preserved-")
    lines = [detail, f"run={run}", f"manifest={manifest}"]
    for label, path in (("run", run), ("manifest", manifest)):
        try:
            st = os.stat(path)
        except OSError as exc:
            lines.append(f"{label}_identity=unstatable: {exc}")
        else:
            lines.append(f"{label}_identity=dev:{st.st_dev} "
                         f"ino:{st.st_ino}")
    note = "\n".join(lines) + "\n"
    try:
        with open(os.path.join(dest, "REASON"), "w") as handle:
            handle.write(note)
    except OSError as exc:
        sys.stderr.write(
            f"WARNING: E2E REASON not preserved: {exc!r}\n")
    try:
        shutil.copy2(manifest, os.path.join(dest,
                                             "manifest.json"))
    except OSError as exc:
        sys.stderr.write(
            f"WARNING: E2E manifest not preserved: {exc!r}\n")
    if os.path.isdir(run):
        try:
            shutil.copytree(run, os.path.join(dest, "run"))
        except OSError as exc:
            sys.stderr.write(
                f"WARNING: E2E run root not preserved: "
                f"{exc!r}\n")
    sys.stderr.write(
        f"PRESERVED E2E retirement evidence in {dest}: "
        f"{detail}\n")
    return dest


@unittest.skipUnless(live_mounts_enabled(),
                     "TT04_LIVE_MOUNTS=1 and sudo -n required")
class LiveBindTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="provision-live-")
        # S130: removal of the ORIGINAL fixture is conditional
        # on proven retirement. Tests that hit failed or
        # uncertain retirement (the E2E verdict, unproven
        # private keeper lives) set _retain_tmp, and the
        # original dir + manifest survive for recovery
        # alongside the outside copies.
        self._retain_tmp = False
        self.addCleanup(self._remove_tmp_unless_retained)
        # S17-round5: join the keeper ns before any mount
        # effect or observation. Failure here is an ERROR,
        # not a skip: the platform prerequisites (sudo,
        # unshare, nsenter) were probed by the class gate,
        # so a failed ensure is a regression to fix.
        provision.ensure_mount_ns()

    def _remove_tmp_unless_retained(self):
        # S130: the tearDown rmtree honors _retain_tmp (set on
        # failed/uncertain retirement), keeping the ORIGINAL
        # fixture for recovery.
        remove_tmp_unless_retained(
            self.tmp, getattr(self, "_retain_tmp", False))

    def test_real_bind_owned_gate(self):
        churn = os.path.join(self.tmp, "churn")
        os.makedirs(churn)
        payload = os.path.join(churn, "payload-b")
        point = os.path.join(churn, "point")
        with open(payload, "wb") as handle:
            handle.write(b"live-payload\n")
        with open(point, "wb") as handle:
            handle.write(b"live-point\n")
        st = os.stat(payload)
        mounted = False
        try:
            proc = sudo("mount", "--bind", payload, point)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            mounted = True
            table = provision.read_mount_table()
            rows = provision.find_mounts(table, point)
            self.assertEqual(len(rows), 1)
            row = rows[0]
            # Genuine bind semantics: the source names the
            # filesystem, never the payload pathname.
            self.assertNotEqual(row["source"],
                                os.path.normpath(payload))
            # S17-round5: the stat arms of the gate see the
            # bind only inside the ns, so the REAL functions
            # run there (an in-ns process reads the ns table
            # directly for /proc/self/mountinfo).
            qualdir = os.path.dirname(provision.__file__)
            gate = sudo(
                sys.executable, "-c",
                "import os, sys\n"
                f"sys.path.insert(0, {qualdir!r})\n"
                "import provision_fs as provision\n"
                f"table = provision.read_mount_table()\n"
                f"print('OWNED', provision.owned_bind_only("
                f"{point!r}, {payload!r}, {st.st_dev}, "
                f"{st.st_ino}, table))\n"
                f"print('PAYLOAD', provision.target_is_payload("
                f"{point!r}, {payload!r}, {st.st_dev}, "
                f"{st.st_ino}))\n")
            self.assertEqual(gate.returncode, 0, gate.stderr)
            self.assertIn("OWNED True", gate.stdout)
            self.assertIn("PAYLOAD True", gate.stdout)
            proc = sudo("umount", point)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            mounted = False
            table = provision.read_mount_table()
            self.assertFalse(provision.find_mounts(table, point))
            self.assertFalse(provision.owned_bind_only(
                point, payload, st.st_dev, st.st_ino, table))
        finally:
            if mounted:
                sudo("umount", point)

    def test_real_driver_bind_restore_cycle(self):
        run_root = os.path.join(self.tmp, "run")
        churn = os.path.join(run_root, "churn")
        os.makedirs(churn)
        payload = os.path.join(churn, "payload-b")
        point = os.path.join(churn, "point")
        with open(payload, "wb") as handle:
            handle.write(b"live-payload\n")
        with open(point, "wb") as handle:
            handle.write(b"live-point\n")
        st = os.stat(payload)
        driver = os.path.join(churn, "driver.py")
        with open(driver, "w") as handle:
            handle.write(provision.CHURN_DRIVER_PY)
        fifo = os.path.join(churn, "cmd.fifo")
        ack = os.path.join(churn, "ack.txt")
        ledger = os.path.join(churn, "ledger.log")
        os.mkfifo(fifo)
        # S17-round5: the driver binds inside the keeper ns
        # (its fifo/ledger/ack files are plain files, visible
        # in both views, so the drive() protocol is unchanged).
        child = subprocess.Popen(
            ["sudo", "-n", "nsenter", f"--mount={live_ns()}",
             sys.executable, driver, run_root,
             fifo, ack, str(st.st_dev), str(st.st_ino)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            close_fds=True)
        try:
            provision.poll_text_contains(ledger, "driver-ready", 20)

            def drive(cmd):
                with open(ack, "w") as handle:
                    handle.write("")
                fd = os.open(fifo, os.O_WRONLY)
                try:
                    os.write(fd, (cmd + "\n").encode())
                finally:
                    os.close(fd)
                text = provision.poll_text_contains(
                    ack, f"{cmd} rc=", 20)
                for line in text.splitlines():
                    if line.startswith(f"{cmd} rc="):
                        return line
                raise AssertionError(f"no ack for {cmd}: {text!r}")

            line = drive("bind-b")
            self.assertIn("bind-b rc=0", line)
            # S17-round5: through the live bind — the host
            # view still shows the covered file.
            self.assertEqual(ns_text(point), "live-payload\n")
            line = drive("restore")
            self.assertIn("restore rc=0", line)
            # S17-round5: read in-ns (discriminating — a
            # failed restore still shows the payload there).
            self.assertEqual(ns_text(point), "live-point\n")
            table = provision.read_mount_table()
            self.assertFalse(provision.find_mounts(table, point))
            line = drive("quit")
            self.assertIn("quit rc=0", line)
            child.wait(timeout=20)
        finally:
            if child.poll() is None:
                try:
                    child.kill()
                except OSError:
                    pass
                try:
                    child.wait(timeout=10)
                except (OSError, subprocess.TimeoutExpired):
                    pass
            sudo("umount", point)

    def test_real_bind_refuses_aux_cleanup(self):
        try:
            probe = os.path.join("/dev/shm", "tt04-probe")
            os.makedirs(probe, exist_ok=True)
            os.rmdir(probe)
        except OSError:
            self.skipTest("no writable /dev/shm")
        root = tempfile.mkdtemp(prefix="tt04-", dir="/dev/shm")
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        canary = os.path.join(root, "canary.txt")
        with open(canary, "wb") as handle:
            handle.write(b"canary\n")
        cover = os.path.join(self.tmp, "cover.txt")
        with open(cover, "wb") as handle:
            handle.write(b"cover\n")
        st = os.stat(root)
        aux = {"path": root, "dev": st.st_dev, "ino": st.st_ino}
        mounted = False
        try:
            proc = sudo("mount", "--bind", cover, canary)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            mounted = True
            failure = provision.cleanup_aux_root(aux)
            self.assertIn("refusing traversal", failure)
        finally:
            if mounted:
                sudo("umount", canary)
        with open(canary, "rb") as handle:
            self.assertEqual(handle.read(), b"canary\n")

    # S27-round3: a same-filesystem bind mounted AFTER the mount
    # snapshot shares the device and is absent from the set — the
    # descriptor-bound mount-ID check still refuses traversal, and
    # neither the source contents nor the shadowed files are
    # deleted through the bind.
    def test_real_bind_after_snapshot_refuses_traversal(self):
        tree = os.path.join(self.tmp, "tree")
        sub = os.path.join(tree, "sub")
        os.makedirs(sub, mode=0o700)
        os.chmod(tree, 0o700)
        os.chmod(sub, 0o700)
        shadowed = os.path.join(sub, "shadowed.txt")
        with open(shadowed, "wb") as handle:
            handle.write(b"shadowed\n")
        src = os.path.join(self.tmp, "src")
        os.makedirs(src, mode=0o700)
        marker = os.path.join(src, "marker.txt")
        with open(marker, "wb") as handle:
            handle.write(b"marker\n")
        # Same-filesystem premise: one shared device, so only the
        # mount ID distinguishes the bind.
        self.assertEqual(os.stat(src).st_dev, os.stat(tree).st_dev)
        # Snapshot FIRST, while no bind exists (ns-routed:
        # also proves no leaked mount sits at the tree).
        snapshot = provision.mount_targets_under(tree)
        self.assertEqual(snapshot, frozenset())
        mounted = False
        try:
            proc = sudo("mount", "--bind", src, sub)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            mounted = True
            # S17-round5: the guard's live arms are
            # descriptor-bound, so the REAL fd_clear_dir runs
            # inside the ns (where the bind lives) with the
            # same stale empty snapshot — the descriptor
            # mount-ID arm must still refuse traversal. The
            # probe runs as root via sudo; the S75/S76
            # controller identity keeps the exclusion gate
            # open for the controller's tree.
            qualdir = os.path.dirname(provision.__file__)
            probe = sudo(
                sys.executable, "-c",
                "import os, sys\n"
                f"sys.path.insert(0, {qualdir!r})\n"
                "import provision_fs as provision\n"
                f"fd = os.open({tree!r}, "
                "os.O_RDONLY | os.O_DIRECTORY)\n"
                "try:\n"
                "    provision.fd_clear_dir(fd, '', "
                "frozenset())\n"
                "    print('TRAVERSAL-COMPLETED')\n"
                "except OSError as exc:\n"
                "    print(f'TRAVERSAL-REFUSED: {exc}')\n"
                "finally:\n"
                "    os.close(fd)\n")
            self.assertEqual(probe.returncode, 0, probe.stderr)
            self.assertIn("mount boundary", probe.stdout)
        finally:
            if mounted:
                bye = sudo("umount", sub)
                self.assertEqual(bye.returncode, 0, bye.stderr)
        with open(marker, "rb") as handle:
            self.assertEqual(handle.read(), b"marker\n")
        with open(shadowed, "rb") as handle:
            self.assertEqual(handle.read(), b"shadowed\n")

    # S17-round3 live: the real privileged retire-mount helper
    # detaches a real bind — the held-FD correspondence and
    # whole-table post-proof must not refuse the genuine happy
    # path (manifest-style record with the live mount ID).
    def test_live_retire_mount_via_helper(self):
        run = os.path.join(self.tmp, "run")
        point = os.path.join(run, "mnt")
        src = os.path.join(self.tmp, "src")
        os.makedirs(point, mode=0o700)
        os.makedirs(src, mode=0o700)
        os.chmod(run, 0o700)
        marker = os.path.join(src, "marker.txt")
        with open(marker, "wb") as handle:
            handle.write(b"marker\n")
        mounted = False
        try:
            proc = sudo("mount", "--bind", src, point)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            mounted = True
            table = provision.read_mount_table()
            rows = provision.find_mounts(table, point)
            self.assertEqual(len(rows), 1)
            row = rows[0]
            # S17-round5: through the live bind (in-ns).
            self.assertTrue(ns_exists(
                os.path.join(point, "marker.txt")))
            proc = sudo(sys.executable, provision.__file__,
                        "retire-mount",
                        "--run-root", run, "--target", point,
                        "--fstype", row["fstype"],
                        "--source", row["source"],
                        "--mnt-id", str(row["mnt_id"]),
                        "--mount-root", row["root"])
            self.assertEqual(proc.returncode, 0,
                             proc.stdout + proc.stderr)
            self.assertIn("retired-mount", proc.stdout)
            mounted = False
            table = provision.read_mount_table()
            self.assertEqual(
                provision.find_mounts(table, point), [])
            self.assertFalse(os.path.exists(
                os.path.join(point, "marker.txt")))
            # S17-round5: move-verify-detach leaves no staging
            # residue behind in the run root.
            leftovers = [name for name in os.listdir(run)
                         if name.startswith(".tt04-retire-")]
            self.assertEqual(leftovers, [])
        finally:
            if mounted:
                bye = sudo("umount", point)
                self.assertEqual(bye.returncode, 0, bye.stderr)

    # S17-round3 live: the real privileged retire-loop helper
    # detaches a real loop attach — the same-fd GET/CLR/GET
    # must clear the validated association. A wrong backing
    # identity first proves the refusal leaves the live
    # association untouched.
    def test_live_retire_loop_via_helper(self):
        run = os.path.join(self.tmp, "run")
        os.makedirs(run, mode=0o700)
        os.chmod(run, 0o700)
        image = os.path.join(run, "loop.img")
        with open(image, "wb") as handle:
            handle.truncate(8 << 20)
        st = os.stat(image)
        proc = sudo("losetup", "--find", "--show", image)
        if proc.returncode != 0:
            self.skipTest(f"losetup unavailable: {proc.stderr}")
        loop = proc.stdout.strip().split()[0]
        self.assertTrue(loop.startswith("/dev/loop"), loop)
        try:
            # Wrong identity: refuse without effect.
            bad = sudo(sys.executable, provision.__file__,
                       "retire-loop",
                       "--run-root", run, "--loop", loop,
                       "--backing-path", image,
                       "--backing-dev", str(st.st_dev),
                       "--backing-ino", str(st.st_ino + 1))
            self.assertNotEqual(bad.returncode, 0)
            self.assertIn("refusing", bad.stdout + bad.stderr)
            live = sudo("losetup", "-j", image)
            self.assertEqual(live.returncode, 0, live.stderr)
            self.assertIn(loop, live.stdout)
            # True identity: detach.
            good = sudo(sys.executable, provision.__file__,
                        "retire-loop",
                        "--run-root", run, "--loop", loop,
                        "--backing-path", image,
                        "--backing-dev", str(st.st_dev),
                        "--backing-ino", str(st.st_ino))
            self.assertEqual(good.returncode, 0,
                             good.stdout + good.stderr)
            self.assertIn("retired-loop", good.stdout)
            gone = sudo("losetup", "-j", image)
            self.assertNotIn(loop, gone.stdout)
        finally:
            sudo("losetup", "-d", loop)

    def _helper_ids(self, path):
        st = os.stat(path)
        return (str(st.st_dev), str(st.st_ino))

    def _run_root_argv(self, run):
        dev, ino = self._helper_ids(run)
        return ["--run-root", run, "--root-dev", dev,
                "--root-ino", ino]

    @staticmethod
    @staticmethod
    def _parse_mounted_line(line, target):
        # S77-round4: delegate to the product parser, so escaped
        # (LF-bearing) reports decode exactly like production.
        parsed = provision._parse_mounted_line(line, target)
        assert parsed is not None, (line, target)
        return parsed

    # S15-round3 live: attach-loop binds a real loop to the
    # verified image natively — losetup sees the association,
    # and retire-loop discharges it.
    def test_live_attach_loop_via_helper(self):
        run = os.path.join(self.tmp, "run")
        os.makedirs(run, mode=0o700)
        os.chmod(run, 0o700)
        image = os.path.join(run, "loop.img")
        with open(image, "wb") as handle:
            handle.truncate(8 << 20)
        dev, ino = self._helper_ids(image)
        proc = sudo(sys.executable, provision.__file__,
                    "attach-loop", *self._run_root_argv(run),
                    "--image", image, "--dev", dev, "--ino", ino)
        if proc.returncode != 0 and (
                "loop-control" in proc.stdout
                or "free loop" in proc.stdout):
            self.skipTest(f"loop unavailable: {proc.stdout}")
        self.assertEqual(proc.returncode, 0,
                         proc.stdout + proc.stderr)
        self.assertTrue(
            proc.stdout.startswith("attached-loop /dev/loop"),
            proc.stdout)
        loop = proc.stdout.split()[1]
        try:
            live = sudo("losetup", "-j", image)
            self.assertEqual(live.returncode, 0, live.stderr)
            self.assertIn(loop, live.stdout)
            bye = sudo(sys.executable, provision.__file__,
                       "retire-loop",
                       "--run-root", run, "--loop", loop,
                       "--backing-path", image,
                       "--backing-dev", dev,
                       "--backing-ino", ino)
            self.assertEqual(bye.returncode, 0,
                             bye.stdout + bye.stderr)
            self.assertIn("retired-loop", bye.stdout)
        finally:
            sudo("losetup", "-d", loop)

    # S15-round3 live: the full verified ext4 chain — make-ext4
    # formats via /dev/fd, attach-loop binds natively, mount-fs
    # mounts on held fds and owns the fresh root (the
    # unprivileged probe write proves the folded chown).
    def test_live_mount_ext4_chain(self):
        run = os.path.join(self.tmp, "run")
        point = os.path.join(run, "mnt")
        os.makedirs(point, mode=0o700)
        os.chmod(run, 0o700)
        image = os.path.join(run, "fs01.img")
        with open(image, "wb") as handle:
            handle.truncate(64 << 20)
        idev, iino = self._helper_ids(image)
        made = sudo(sys.executable, provision.__file__,
                    "make-ext4", *self._run_root_argv(run),
                    "--image", image, "--dev", idev, "--ino",
                    iino)
        self.assertEqual(made.returncode, 0,
                         made.stdout + made.stderr)
        self.assertIn("made-ext4", made.stdout)
        with open(image, "rb") as handle:
            handle.seek(0x438)
            self.assertEqual(handle.read(2), b"\x53\xef")
        bound = sudo(sys.executable, provision.__file__,
                     "attach-loop", *self._run_root_argv(run),
                     "--image", image, "--dev", idev, "--ino",
                     iino)
        if bound.returncode != 0 and (
                "loop-control" in bound.stdout
                or "free loop" in bound.stdout):
            self.skipTest(f"loop unavailable: {bound.stdout}")
        self.assertEqual(bound.returncode, 0,
                         bound.stdout + bound.stderr)
        loop = bound.stdout.split()[1]
        mounted = False
        try:
            tdev, tino = self._helper_ids(point)
            mnt = sudo(sys.executable, provision.__file__,
                       "mount-fs", *self._run_root_argv(run),
                       "--target", point,
                       "--target-dev", tdev, "--target-ino", tino,
                       "--fstype", "ext4", "--loop", loop,
                       "--backing-dev", idev, "--backing-ino",
                       iino, "--own-uid", str(os.geteuid()),
                       "--own-gid", str(os.getegid()))
            self.assertEqual(mnt.returncode, 0,
                             mnt.stdout + mnt.stderr)
            line = mnt.stdout.splitlines()[0]
            mnt_id, source, super_opts = self._parse_mounted_line(
                line, point)
            self.assertIn("rw", super_opts)
            # The kernel echoes the fd-bound source literally.
            self.assertTrue(source.startswith("/dev/fd/"), source)
            mounted = True
            table = provision.read_mount_table()
            rows = provision.find_mounts(table, point)
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["mnt_id"], mnt_id)
            self.assertEqual(rows[0]["fstype"], "ext4")
            self.assertEqual(rows[0]["source"], source)
            # S71-round5: the REAL descriptor correspondence
            # against the live mount (in-ns: the host view
            # sees the covered dir). Match, wrong-node, and
            # changed-observation (doctored row ID) verdicts.
            qualdir = os.path.dirname(provision.__file__)
            corr = sudo(
                sys.executable, "-c",
                "import os, sys\n"
                f"sys.path.insert(0, {qualdir!r})\n"
                "import provision_fs as provision\n"
                f"row = {{'mnt_id': {mnt_id}}}\n"
                f"bad = {{'mnt_id': {mnt_id + 10000}}}\n"
                f"print('MATCH1', provision._mount_matches_loop("
                f"{point!r}, {loop!r}, row))\n"
                "print('MATCH2', "
                "provision._mount_matches_loop("
                f"{point!r}, '/dev/loop-control', row))\n"
                f"print('MATCH3', provision._mount_matches_loop("
                f"{point!r}, {loop!r}, bad))\n")
            self.assertEqual(corr.returncode, 0, corr.stderr)
            self.assertIn("MATCH1 True", corr.stdout)
            self.assertIn("MATCH2 False", corr.stdout)
            self.assertIn("MATCH3 False", corr.stdout)
            # Folded ownership: our own write lands
            # (S17-round5: through the live ext4 mount, so
            # the unprivileged write and the owner stat run
            # inside the ns).
            probe = os.path.join(point, "probe.txt")
            ns_write_user(probe, "hello\n")
            stat_p = sudo("stat", "-c", "%u", point)
            self.assertEqual(stat_p.returncode, 0,
                             stat_p.stderr)
            self.assertEqual(stat_p.stdout.strip(),
                             str(os.geteuid()))
            row = rows[0]
            bye = sudo(sys.executable, provision.__file__,
                       "retire-mount",
                       "--run-root", run, "--target", point,
                       "--fstype", row["fstype"],
                       "--source", row["source"],
                       "--mnt-id", str(row["mnt_id"]),
                       "--mount-root", row["root"])
            self.assertEqual(bye.returncode, 0,
                             bye.stdout + bye.stderr)
            self.assertIn("retired-mount", bye.stdout)
            mounted = False
            free = sudo(sys.executable, provision.__file__,
                        "retire-loop",
                        "--run-root", run, "--loop", loop,
                        "--backing-path", image,
                        "--backing-dev", idev,
                        "--backing-ino", iino)
            self.assertEqual(free.returncode, 0,
                             free.stdout + free.stderr)
        finally:
            if mounted:
                sudo("umount", point)
            sudo("losetup", "-d", loop)

    # S15-round3 live: mount-fs assembles a real overlay stack
    # from verified layers — the kernel records the /dev/fd
    # layer spellings, the merged view serves lower content,
    # and an upper write lands in our upper.
    def test_live_mount_overlay(self):
        run = os.path.join(self.tmp, "run")
        role = os.path.join(run, "ov")
        for sub in ("lower", "upper", "work", "merged"):
            os.makedirs(os.path.join(role, sub), mode=0o700)
        os.chmod(run, 0o700)
        os.chmod(role, 0o700)
        with open(os.path.join(role, "lower", "shared.txt"),
                  "w") as handle:
            handle.write("lower-original\n")
        target = os.path.join(role, "merged")
        # S81-round5: plant the binding canary the helper
        # reads from held upper (never argv) for overlay
        # post-mount binding.
        canary = "live-canary-%d" % os.getpid()
        with open(os.path.join(
                role, "upper",
                provision.MOUNT_CANARY_NAME), "w") as handle:
            handle.write(canary)
        tdev, tino = self._helper_ids(target)
        argv = [sys.executable, provision.__file__,
               "mount-fs", *self._run_root_argv(run),
               "--target", target,
               "--target-dev", tdev, "--target-ino", tino,
               "--fstype", "overlay"]
        for name in ("lower", "upper", "work"):
            dev, ino = self._helper_ids(
                os.path.join(role, name))
            argv += ["--layer",
                    f"{name}={role}/{name}:{dev}:{ino}"]
        mounted = False
        try:
            mnt = sudo(*argv)
            self.assertEqual(mnt.returncode, 0,
                             mnt.stdout + mnt.stderr)
            line = mnt.stdout.splitlines()[0]
            mnt_id, source, super_opts = self._parse_mounted_line(
                line, target)
            self.assertEqual(source, "overlay")
            self.assertIn("lowerdir=/dev/fd/", super_opts)
            mounted = True
            table = provision.read_mount_table()
            rows = provision.find_mounts(table, target)
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["mnt_id"], mnt_id)
            self.assertEqual(rows[0]["fstype"], "overlay")
            # S17-round5: through the live overlay (the
            # upperdir read below stays direct — plain dir).
            self.assertEqual(
                ns_text(os.path.join(target, "shared.txt")),
                "lower-original\n")
            ns_write_user(
                os.path.join(target, "upper-only.txt"),
                "upper-only\n")
            with open(os.path.join(role, "upper",
                                   "upper-only.txt")) as fh:
                self.assertEqual(fh.read(), "upper-only\n")
            row = rows[0]
            bye = sudo(sys.executable, provision.__file__,
                       "retire-mount",
                       "--run-root", run, "--target", target,
                       "--fstype", row["fstype"],
                       "--source", row["source"],
                       "--mnt-id", str(row["mnt_id"]),
                       "--mount-root", row["root"])
            self.assertEqual(bye.returncode, 0,
                             bye.stdout + bye.stderr)
            mounted = False
        finally:
            if mounted:
                sudo("umount", target)

    # S81-round5 live: the helper pins the fresh mount
    # before its post-mount window opens, so a privileged
    # regular umount inside the window goes EBUSY — the swap
    # cannot even start, and the helper reports OUR mount
    # (ID, content, folded ownership all prove it).
    def test_live_mount_window_pin_blocks_umount(self):
        if os.geteuid() == 0:
            self.skipTest("needs a non-root controller")
        run = os.path.join(self.tmp, "run")
        role = os.path.join(run, "ov")
        for sub in ("lower", "upper", "work", "merged"):
            os.makedirs(os.path.join(role, sub), mode=0o700)
        os.chmod(run, 0o700)
        os.chmod(role, 0o700)
        canary = "live-canary-%d" % os.getpid()
        with open(os.path.join(
                role, "upper",
                provision.MOUNT_CANARY_NAME), "w") as handle:
            handle.write(canary)
        target = os.path.join(role, "merged")
        tdev, tino = self._helper_ids(target)
        argv = [sys.executable, provision.__file__,
               "mount-fs", *self._run_root_argv(run),
               "--target", target,
               "--target-dev", tdev, "--target-ino", tino,
               "--fstype", "overlay",
               "--own-uid", str(os.geteuid()),
               "--own-gid", str(os.getegid())]
        for name in ("lower", "upper", "work"):
            dev, ino = self._helper_ids(
                os.path.join(role, name))
            argv += ["--layer",
                    f"{name}={role}/{name}:{dev}:{ino}"]

        def live_row():
            table = provision.read_mount_table()
            rows = provision.find_mounts(table, target)
            if len(rows) == 1:
                return rows[0]
            return None

        def poll_row(timeout):
            deadline = time.time() + timeout
            while time.time() < deadline:
                row = live_row()
                if row is not None:
                    return row
                time.sleep(0.2)
            return None

        helper = subprocess.Popen(
            ["sudo", "-n", "nsenter",
             f"--mount={live_ns()}", "env",
             "S81_HELPER_POST_MOUNT_DELAY_MS=20000",
             *argv],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True)
        try:
            first = poll_row(60)
            self.assertIsNotNone(
                first, "helper never mounted the target")
            self.assertIsNone(
                helper.poll(),
                "helper finished before the window opened "
                "(delay hook inert?)")
            # The swap cannot start: our pin holds EBUSY.
            bye = sudo("umount", target)
            self.assertNotEqual(bye.returncode, 0)
            self.assertIn("busy", bye.stderr.lower())
            out = helper.communicate(timeout=120)[0]
            self.assertEqual(helper.returncode, 0, out)
            line = out.splitlines()[0]
            mnt_id, source, _ = self._parse_mounted_line(
                line, target)
            self.assertEqual(source, "overlay")
            # Reported OUR mount: live ID, content, and the
            # folded chown all agree.
            self.assertEqual(live_row()["mnt_id"], mnt_id)
            self.assertEqual(
                ns_text(os.path.join(
                    target, provision.MOUNT_CANARY_NAME)),
                canary)
            stat_p = sudo("stat", "-c", "%u", target)
            self.assertEqual(stat_p.stdout.strip(),
                             str(os.geteuid()))
        finally:
            if helper.poll() is None:
                helper.kill()
                helper.wait()
            sudo("umount", target)

    # S81-round5 live: a lazy detach defeats the pin, but the
    # detached mount keeps its ID (no recycling while held),
    # so the pin cross-check refuses the replacement
    # deterministically — even carrying the COPIED correct
    # token. The refusal reason proves content-independence
    # (a mount change, never a canary mismatch), the
    # stranger is left in place, and no chown touches it
    # although --own-uid/gid was given.
    def test_live_mount_lazy_replacement_refuses_copied_token(
            self):
        if os.geteuid() == 0:
            self.skipTest("needs a non-root controller")
        run = os.path.join(self.tmp, "run")
        role = os.path.join(run, "ov")
        for sub in ("lower", "upper", "work", "merged"):
            os.makedirs(os.path.join(role, sub), mode=0o700)
        os.chmod(run, 0o700)
        os.chmod(role, 0o700)
        canary = "live-canary-%d" % os.getpid()
        with open(os.path.join(
                role, "upper",
                provision.MOUNT_CANARY_NAME), "w") as handle:
            handle.write(canary)
        # Foreign stack: plausible overlay, the COPIED
        # correct token (read from our upper, as any
        # privileged interposer could), and root-owned upper
        # so a folded chown would be visible.
        fx = os.path.join(run, "fx")
        for sub in ("flower", "fupper", "fwork"):
            os.makedirs(os.path.join(fx, sub), mode=0o700)
        with open(os.path.join(
                fx, "fupper",
                provision.MOUNT_CANARY_NAME), "w") as handle:
            handle.write(canary)
        fupper = os.path.join(fx, "fupper")
        own = sudo("chown", "0:0", fupper)
        self.assertEqual(own.returncode, 0, own.stderr)
        target = os.path.join(role, "merged")
        tdev, tino = self._helper_ids(target)
        argv = [sys.executable, provision.__file__,
               "mount-fs", *self._run_root_argv(run),
               "--target", target,
               "--target-dev", tdev, "--target-ino", tino,
               "--fstype", "overlay",
               "--own-uid", str(os.geteuid()),
               "--own-gid", str(os.getegid())]
        for name in ("lower", "upper", "work"):
            dev, ino = self._helper_ids(
                os.path.join(role, name))
            argv += ["--layer",
                    f"{name}={role}/{name}:{dev}:{ino}"]

        def live_row():
            table = provision.read_mount_table()
            rows = provision.find_mounts(table, target)
            if len(rows) == 1:
                return rows[0]
            return None

        def poll_row(timeout, different_super_from=None):
            deadline = time.time() + timeout
            while time.time() < deadline:
                row = live_row()
                if row is not None and (
                        different_super_from is None
                        or row["super"] != different_super_from):
                    return row
                time.sleep(0.2)
            return None

        helper = subprocess.Popen(
            ["sudo", "-n", "nsenter",
             f"--mount={live_ns()}", "env",
             "S81_HELPER_POST_MOUNT_DELAY_MS=20000",
             *argv],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True)
        try:
            first = poll_row(60)
            self.assertIsNotNone(
                first, "helper never mounted the target")
            self.assertIsNone(
                helper.poll(),
                "helper finished before the replacement "
                "window opened (delay hook inert?)")
            # Lazy detach + plant inside the window.
            bye = sudo("umount", "-l", target)
            self.assertEqual(bye.returncode, 0, bye.stderr)
            opts = ("lowerdir=%s,upperdir=%s,workdir=%s"
                    % (os.path.join(fx, "flower"), fupper,
                       os.path.join(fx, "fwork")))
            plant = sudo("mount", "-t", "overlay", "overlay",
                         "-o", opts, target)
            self.assertEqual(plant.returncode, 0,
                             plant.stderr)
            second = poll_row(30,
                              different_super_from=first["super"])
            self.assertIsNotNone(
                second, "replacement mount never appeared")
            self.assertEqual(second["fstype"], "overlay")
            self.assertEqual(second["source"], "overlay")
            # The plant really carries the copied token...
            seen = sudo("cat", os.path.join(
                target, provision.MOUNT_CANARY_NAME))
            self.assertEqual(seen.returncode, 0,
                             seen.stderr)
            self.assertEqual(seen.stdout, canary)
            # ...yet the helper refuses by acquisition (mount
            # change), never by content.
            out = helper.communicate(timeout=120)[0]
            self.assertEqual(helper.returncode, 1, out)
            self.assertIn("FAILED-UNCERTAIN", out)
            self.assertIn("changed during effect", out)
            self.assertNotIn("canary mismatch", out)
            # No chown touched the stranger: root-owned upper
            # unchanged, occupant left in place.
            fst = os.stat(fupper)
            self.assertEqual((fst.st_uid, fst.st_gid),
                             (0, 0))
            self.assertEqual(live_row()["super"],
                             second["super"])
        finally:
            if helper.poll() is None:
                helper.kill()
                helper.wait()
            sudo("umount", target)
            # Restore ownership so plain cleanup can rmtree.
            sudo("chown", "-R",
                 "%d:%d" % (os.geteuid(), os.getegid()), fx)

    # S81-round6 live: a copied-token replacement planted
    # BEFORE the pin open refuses at the pin probe. The
    # clone carries our C1 token, so the pin opens it and
    # every content gate passes — but the fresh challenge
    # written through the pin drains to the clone's upper,
    # never to ours. The refusal precedes any chown (the
    # root-owned foreign upper is unchanged) and the clone
    # is left in place. Deterministic via the pre-pin delay
    # window (no blind preemption luck).
    def test_live_mount_pre_pin_clone_refuses_pin_probe(self):
        if os.geteuid() == 0:
            self.skipTest("needs a non-root controller")
        run = os.path.join(self.tmp, "run")
        role = os.path.join(run, "ov")
        for sub in ("lower", "upper", "work", "merged"):
            os.makedirs(os.path.join(role, sub), mode=0o700)
        os.chmod(run, 0o700)
        os.chmod(role, 0o700)
        canary = "live-canary-%d" % os.getpid()
        token_path = os.path.join(
            role, "upper", provision.MOUNT_CANARY_NAME)
        fd = os.open(token_path,
                     os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                     0o600)
        try:
            os.write(fd, canary.encode("ascii"))
        finally:
            os.close(fd)
        # Foreign clone: plausible overlay, the COPIED
        # correct token, and root-owned upper so a folded
        # chown would be visible.
        fx = os.path.join(run, "fx")
        for sub in ("flower", "fupper", "fwork"):
            os.makedirs(os.path.join(fx, sub), mode=0o700)
        with open(os.path.join(
                fx, "fupper",
                provision.MOUNT_CANARY_NAME), "w") as handle:
            handle.write(canary)
        fupper = os.path.join(fx, "fupper")
        own = sudo("chown", "0:0", fupper)
        self.assertEqual(own.returncode, 0, own.stderr)
        target = os.path.join(role, "merged")
        tdev, tino = self._helper_ids(target)
        argv = [sys.executable, provision.__file__,
               "mount-fs", *self._run_root_argv(run),
               "--target", target,
               "--target-dev", tdev, "--target-ino", tino,
               "--fstype", "overlay",
               "--own-uid", str(os.geteuid()),
               "--own-gid", str(os.getegid())]
        for name in ("lower", "upper", "work"):
            dev, ino = self._helper_ids(
                os.path.join(role, name))
            argv += ["--layer",
                    f"{name}={role}/{name}:{dev}:{ino}"]

        def live_row():
            table = provision.read_mount_table()
            rows = provision.find_mounts(table, target)
            if len(rows) == 1:
                return rows[0]
            return None

        def poll_row(timeout, different_super_from=None):
            deadline = time.time() + timeout
            while time.time() < deadline:
                row = live_row()
                if row is not None and (
                        different_super_from is None
                        or row["super"] != different_super_from):
                    return row
                time.sleep(0.2)
            return None

        helper = subprocess.Popen(
            ["sudo", "-n", "nsenter",
             f"--mount={live_ns()}", "env",
             "S74_PRE_PIN_DELAY_MS=20000",
             *argv],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True)
        try:
            first = poll_row(60)
            self.assertIsNotNone(
                first, "helper never mounted the target")
            self.assertIsNone(
                helper.poll(),
                "helper finished before the pre-pin window "
                "opened (delay hook inert?)")
            # Lazy detach + copied-token plant inside the
            # PRE-PIN window (ours is unpinned, so the lazy
            # detach destroys it — the clone is the sole
            # occupant when the pin opens).
            bye = sudo("umount", "-l", target)
            self.assertEqual(bye.returncode, 0, bye.stderr)
            opts = ("lowerdir=%s,upperdir=%s,workdir=%s"
                    % (os.path.join(fx, "flower"), fupper,
                       os.path.join(fx, "fwork")))
            plant = sudo("mount", "-t", "overlay", "overlay",
                         "-o", opts, target)
            self.assertEqual(plant.returncode, 0,
                             plant.stderr)
            second = poll_row(30,
                              different_super_from=first["super"])
            self.assertIsNotNone(
                second, "replacement mount never appeared")
            self.assertEqual(second["fstype"], "overlay")
            # The plant really carries the copied token...
            seen = sudo("cat", os.path.join(
                target, provision.MOUNT_CANARY_NAME))
            self.assertEqual(seen.returncode, 0,
                             seen.stderr)
            self.assertEqual(seen.stdout, canary)
            # ...yet the helper refuses at the pin probe
            # (drain failure), never by content.
            out = helper.communicate(timeout=120)[0]
            self.assertEqual(helper.returncode, 1, out)
            self.assertIn("FAILED-UNCERTAIN", out)
            self.assertIn("pin probe", out)
            self.assertNotIn("canary mismatch", out)
            # The challenge reached the clone's upper (and
            # only there), 0600, root-written.
            listing = sudo("ls", "-a", fupper)
            self.assertEqual(listing.returncode, 0,
                             listing.stderr)
            probes = [
                name for name in listing.stdout.split()
                if name.startswith(
                    provision.MOUNT_PROBE_PREFIX)]
            self.assertEqual(len(probes), 1)
            mode = sudo("stat", "-c", "%a:%u",
                        os.path.join(fupper, probes[0]))
            self.assertEqual(mode.stdout.strip(), "600:0")
            self.assertEqual(
                [name for name in os.listdir(
                    os.path.join(role, "upper"))
                 if name.startswith(
                     provision.MOUNT_PROBE_PREFIX)], [])
            # No chown touched the stranger: root-owned upper
            # unchanged, occupant left in place.
            fst = os.stat(fupper)
            self.assertEqual((fst.st_uid, fst.st_gid),
                             (0, 0))
            self.assertEqual(live_row()["super"],
                             second["super"])
        finally:
            if helper.poll() is None:
                helper.kill()
                helper.wait()
            sudo("umount", target)
            # Restore ownership so plain cleanup can rmtree.
            sudo("chown", "-R",
                 "%d:%d" % (os.geteuid(), os.getegid()), fx)

    # S74-round4 live: a target renamed around the effect is
    # reported as moved (mount ID + observed mountpoint),
    # never as a false "missing" failure. A live mountpoint
    # itself is EBUSY, so the rename moves the role directory
    # (parent) inside the post-mount delay window; the mount
    # follows to the new path. The handler cannot tell this
    # from the finding's pre-mount rename (both present as a
    # diff-added row at a non-verified name), so this
    # exercises the moved path on a real kernel move with no
    # extra hook. The ID in the report matches the live row.
    def test_live_mount_moved_target_reports_recovery_id(self):
        run = os.path.join(self.tmp, "run")
        role = os.path.join(run, "ov")
        for sub in ("lower", "upper", "work", "merged"):
            os.makedirs(os.path.join(role, sub), mode=0o700)
        os.chmod(run, 0o700)
        os.chmod(role, 0o700)
        canary = "live-canary-%d" % os.getpid()
        with open(os.path.join(
                role, "upper",
                provision.MOUNT_CANARY_NAME), "w") as handle:
            handle.write(canary)
        target = os.path.join(role, "merged")
        role2 = os.path.join(run, "ov2")
        moved = os.path.join(role2, "merged")
        tdev, tino = self._helper_ids(target)
        argv = [sys.executable, provision.__file__,
               "mount-fs", *self._run_root_argv(run),
               "--target", target,
               "--target-dev", tdev, "--target-ino", tino,
               "--fstype", "overlay"]
        for name in ("lower", "upper", "work"):
            dev, ino = self._helper_ids(
                os.path.join(role, name))
            argv += ["--layer",
                    f"{name}={role}/{name}:{dev}:{ino}"]

        def live_rows_at(path):
            table = provision.read_mount_table()
            return provision.find_mounts(table, path)

        def poll_rows_at(path, timeout):
            deadline = time.time() + timeout
            while time.time() < deadline:
                rows = live_rows_at(path)
                if rows:
                    return rows
                time.sleep(0.2)
            return []

        # S17-round5: the helper mounts inside the ns.
        helper = subprocess.Popen(
            ["sudo", "-n", "nsenter",
             f"--mount={live_ns()}", "env",
             "S81_HELPER_POST_MOUNT_DELAY_MS=20000",
             *argv],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True)
        try:
            first = poll_rows_at(target, 60)
            self.assertEqual(len(first), 1,
                             "helper never mounted the target")
            self.assertIsNone(
                helper.poll(),
                "helper finished before the move window "
                "opened (delay hook inert?)")
            # Rename the role directory inside the helper's
            # post-mount window; the mount follows to the new
            # path (renaming the live mountpoint itself is
            # EBUSY, so the finding's window is pre-mount —
            # the handler sees the same diff either way).
            os.rename(role, role2)
            second = poll_rows_at(moved, 30)
            self.assertEqual(len(second), 1,
                             "moved mount never appeared")
            self.assertEqual(live_rows_at(target), [])
            # S17-round5: through the moved mount (in-ns).
            self.assertEqual(
                ns_text(os.path.join(
                    moved, provision.MOUNT_CANARY_NAME)),
                canary)
            out = helper.communicate(timeout=120)[0]
            self.assertEqual(helper.returncode, 1, out)
            self.assertIn("FAILED-MOVED", out)
            parsed = provision._parse_moved_report(out)
            self.assertIsNotNone(parsed, out)
            mnt_id, observed = parsed
            self.assertEqual(observed, moved)
            self.assertEqual(mnt_id, second[0]["mnt_id"])
        finally:
            if helper.poll() is None:
                helper.kill()
                helper.wait()
            sudo("umount", moved)
            sudo("umount", target)

    # S74-round6 live: the role parent is renamed OUTSIDE the
    # run root BEFORE PIN acquisition (pre-pin delay window).
    # Mount through the held operand succeeds, the pin fails,
    # and — S108/S136: the token alone is copyable, so no pin
    # means no held-upper binding proof and NO authoritative
    # moved report. The helper reports FAILED-UNCERTAIN with
    # the live ID/location as non-authoritative observation
    # text only. Reconcile keeps ID-less pending custody;
    # ACTUAL cleanup then fails loudly (absence unprovable,
    # custody kept pending) with the mount still live at the
    # escaped path — a location cleanup never learns — and
    # custody retained, never a silent discharge past the
    # empty name and the run-root-only sweep. No chown
    # touches the moved-but-unpinned mount although
    # --own-uid/gid was given.
    def test_live_mount_pre_pin_rename_outside_recovers(self):
        import contextlib
        import io
        import types
        run = os.path.join(self.tmp, "run")
        role = os.path.join(run, "ov")
        for sub in ("lower", "upper", "work", "merged"):
            os.makedirs(os.path.join(role, sub), mode=0o700)
        os.chmod(run, 0o700)
        os.chmod(role, 0o700)
        canary = "live-canary-%d" % os.getpid()
        with open(os.path.join(
                role, "upper",
                provision.MOUNT_CANARY_NAME), "w") as handle:
            handle.write(canary)
        target = os.path.join(role, "merged")
        escaped_role = os.path.join(self.tmp, "escaped")
        escaped = os.path.join(escaped_role, "merged")
        tdev, tino = self._helper_ids(target)
        argv = [sys.executable, provision.__file__,
               "mount-fs", *self._run_root_argv(run),
               "--target", target,
               "--target-dev", tdev, "--target-ino", tino,
               "--fstype", "overlay",
               "--own-uid", "0", "--own-gid", "0"]
        for name in ("lower", "upper", "work"):
            dev, ino = self._helper_ids(
                os.path.join(role, name))
            argv += ["--layer",
                    f"{name}={role}/{name}:{dev}:{ino}"]

        def live_rows_at(path):
            table = provision.read_mount_table()
            return provision.find_mounts(table, path)

        def poll_rows_at(path, timeout):
            deadline = time.time() + timeout
            while time.time() < deadline:
                rows = live_rows_at(path)
                if rows:
                    return rows
                time.sleep(0.2)
            return []

        helper = subprocess.Popen(
            ["sudo", "-n", "nsenter",
             f"--mount={live_ns()}", "env",
             "S74_PRE_PIN_DELAY_MS=20000",
             *argv],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True)
        try:
            first = poll_rows_at(target, 60)
            self.assertEqual(len(first), 1,
                             "helper never mounted the target")
            self.assertIsNone(
                helper.poll(),
                "helper finished before the pre-pin window "
                "opened (delay hook inert?)")
            # Rename the role PARENT outside the run root
            # before pin acquisition; the mount follows.
            os.rename(role, escaped_role)
            second = poll_rows_at(escaped, 30)
            self.assertEqual(len(second), 1,
                             "moved mount never appeared")
            self.assertEqual(live_rows_at(target), [])
            out = helper.communicate(timeout=120)[0]
            self.assertEqual(helper.returncode, 1, out)
            # S136: uncertainty, not an authoritative moved
            # report — the live ID/location appear only as
            # non-authoritative observation text for manual
            # retirement, never parsed into custody.
            self.assertIn("FAILED-UNCERTAIN", out)
            self.assertNotIn("FAILED-MOVED", out)
            self.assertIsNone(
                provision._parse_moved_report(out), out)
            self.assertIn("unpinned moved candidate", out)
            self.assertIn("lacks held-upper binding", out)
            self.assertIn(
                f"(mnt={second[0]['mnt_id']} observed at ",
                out)
            # No chown on the moved-but-unpinned mount: the
            # upper it carries is still controller-owned.
            fst = os.stat(os.path.join(escaped_role, "upper"))
            self.assertEqual((fst.st_uid, fst.st_gid),
                             (os.geteuid(), os.getegid()))
            # Reconcile through production code: the
            # controller normalizes the helper report and
            # keeps ID-keyed pending custody.
            manifest_path = os.path.join(self.tmp,
                                         "manifest.json")
            doc = provision.fresh_manifest(run, False)
            st = os.stat(run)
            doc["run_root_identity"] = {"dev": st.st_dev,
                                        "ino": st.st_ino}
            provision.record_pending_acquisition(doc, {
                "kind": "mount", "key": target, "role": "ov",
                "target": target, "fstype": "overlay",
                "source": "overlay", "expect_super": [],
                "canary": canary})
            failure = provision._normalize_mount_failure(
                target, helper.returncode, out, "")
            adopted = provision.reconcile_mount_effect(
                doc, run, "ov", target,
                {"fstype": "overlay", "source": "overlay",
                 "expect_super": []},
                canary=(provision.MOUNT_CANARY_NAME, canary),
                failure=failure)
            self.assertIsNone(adopted)
            pendings = doc["pending_acquisitions"]
            self.assertEqual(len(pendings), 1)
            # S136: ID-less pending custody — the unverified
            # observation text never becomes recovery identity.
            self.assertNotIn("mnt_id", pendings[0])
            self.assertNotIn("observed_target", pendings[0])
            self.assertIn("uncertain",
                          pendings[0].get("detail", ""))
            with open(manifest_path, "w") as handle:
                json.dump(doc, handle)
            # ACTUAL cleanup: loud failure — the target is
            # empty but the outcome is uncertain, so absence
            # is unprovable and custody stays pending. Cleanup
            # never learns the escaped location (no ID-keyed
            # recovery without binding proof) and retires
            # nothing blind. Custody retained, never discharged.
            args = types.SimpleNamespace(run_root=run,
                                         manifest=manifest_path)
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = provision.cleanup_command(args)
            self.assertEqual(rc, 1, buf.getvalue())
            self.assertIn("cleanup: FAILED", buf.getvalue())
            self.assertIn("cannot prove absence",
                          buf.getvalue())
            self.assertIn("custody kept pending",
                          buf.getvalue())
            self.assertNotIn(escaped, buf.getvalue())
            live = live_rows_at(escaped)
            self.assertEqual(len(live), 1)
            self.assertEqual(live[0]["mnt_id"],
                             second[0]["mnt_id"])
            kept = json.loads(open(manifest_path).read())
            self.assertEqual(
                len(kept["pending_acquisitions"]), 1)
            self.assertNotIn(
                "mnt_id", kept["pending_acquisitions"][0])
            self.assertNotIn(
                "observed_target",
                kept["pending_acquisitions"][0])
        finally:
            if helper.poll() is None:
                helper.kill()
                helper.wait()
            sudo("umount", escaped)
            sudo("umount", target)

    # S75-round4 live: a real mixed-ownership caller-to-root
    # cleanup. The unprivileged pass meets the root-owned
    # workdir and escalates; the sudo'd remover — running as
    # root with SUDO_UID naming the controller — accepts the
    # controller's exclusive directories instead of rejecting
    # the normal user's tree, and retires everything.
    def test_live_cleanup_mixed_ownership_via_sudo(self):
        import json as _json
        import types as _types
        if os.geteuid() == 0:
            self.skipTest("needs a non-root controller")
        run = os.path.join(self.tmp, "run")
        os.makedirs(os.path.join(run, "data"), mode=0o700)
        os.makedirs(os.path.join(run, "work"), mode=0o700)
        os.chmod(run, 0o700)
        with open(os.path.join(run, "data",
                               "note.txt"), "w") as handle:
            handle.write("controller data\n")
        # A root-owned workdir, as an overlay mount would
        # leave it: defeats the unprivileged pass.
        mk = sudo("chown", "0:0", os.path.join(run, "work"))
        self.assertEqual(mk.returncode, 0, mk.stderr)
        st = os.stat(run)
        manifest = os.path.join(self.tmp, "manifest.json")
        doc = provision.fresh_manifest(run, False)
        doc["run_root_identity"] = {"dev": st.st_dev,
                                    "ino": st.st_ino}
        with open(manifest, "w") as handle:
            handle.write(_json.dumps(doc))
        args = _types.SimpleNamespace(run_root=run,
                                      manifest=manifest)
        try:
            rc = provision.cleanup_command(args)
        finally:
            # Restore ownership so plain cleanup can rmtree
            # whatever a failure leaves behind.
            sudo("chown", "-R",
                 "%d:%d" % (os.geteuid(), os.getegid()), run)
        self.assertEqual(rc, 0)
        # R11-010: proven absence, not exists()-silence — an
        # unstatable survivor must fail loudly, not pass.
        self.assertTrue(fixture_root_gone(run))

    # S76-round4 live: the same 0775 self-owned parent stays
    # admissible across the controller-to-helper UID transition.
    # The helper runs as root with SUDO_UID naming the
    # controller, so the privileged mount succeeds; pre-fix the
    # helper refused it as foreign-owned. Scrubbing SUDO_UID
    # restores the refusal, pinning the mechanism.
    def test_live_mount_under_shared_parent_cross_uid(self):
        base = os.path.join(self.tmp, "s76-shared")
        os.makedirs(base, mode=0o700)
        os.chmod(base, 0o775)
        run = os.path.join(base, "run")
        role = os.path.join(run, "ov")
        for sub in ("lower", "upper", "work", "merged"):
            os.makedirs(os.path.join(role, sub), mode=0o700)
        os.chmod(run, 0o700)
        os.chmod(role, 0o700)
        with open(os.path.join(role, "lower", "shared.txt"),
                  "w") as handle:
            handle.write("lower-original\n")
        target = os.path.join(role, "merged")
        # S81-round5: plant the binding canary the helper
        # reads from held upper (never argv) for overlay
        # post-mount binding.
        canary = "live-canary-%d" % os.getpid()
        with open(os.path.join(
                role, "upper",
                provision.MOUNT_CANARY_NAME), "w") as handle:
            handle.write(canary)
        tdev, tino = self._helper_ids(target)
        argv = [sys.executable, provision.__file__,
               "mount-fs", *self._run_root_argv(run),
               "--target", target,
               "--target-dev", tdev, "--target-ino", tino,
               "--fstype", "overlay"]
        for name in ("lower", "upper", "work"):
            dev, ino = self._helper_ids(
                os.path.join(role, name))
            argv += ["--layer",
                    f"{name}={role}/{name}:{dev}:{ino}"]
        # Controller side admits the shared parent first.
        guard = provision.RootAuthority(run)
        try:
            guard.verify()
        finally:
            guard.close()
        # Without the controller identity the helper refuses.
        scrubbed = sudo("env", "-u", "SUDO_UID", *argv)
        self.assertEqual(scrubbed.returncode, 1,
                         scrubbed.stdout + scrubbed.stderr)
        self.assertIn("foreign owner", scrubbed.stdout)
        # With it (plain sudo) the mount succeeds.
        mounted = False
        try:
            mnt = sudo(*argv)
            self.assertEqual(mnt.returncode, 0,
                             mnt.stdout + mnt.stderr)
            line = mnt.stdout.splitlines()[0]
            mnt_id, source, _ = self._parse_mounted_line(
                line, target)
            self.assertEqual(source, "overlay")
            mounted = True
            table = provision.read_mount_table()
            rows = provision.find_mounts(table, target)
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["mnt_id"], mnt_id)
            # S17-round5: through the live overlay (in-ns).
            self.assertEqual(
                ns_text(os.path.join(target, "shared.txt")),
                "lower-original\n")
            row = rows[0]
            bye = sudo(sys.executable, provision.__file__,
                       "retire-mount",
                       "--run-root", run, "--target", target,
                       "--fstype", row["fstype"],
                       "--source", row["source"],
                       "--mnt-id", str(row["mnt_id"]),
                       "--mount-root", row["root"])
            self.assertEqual(bye.returncode, 0,
                             bye.stdout + bye.stderr)
            mounted = False
        finally:
            if mounted:
                sudo("umount", target)

    # S77-round4 live: the full helper round trip with an
    # admitted LF target — mount, escaped success report,
    # fingerprint match against the live table, content check,
    # and retirement all carry the real newline.
    def test_live_mount_overlay_lf_target(self):
        run = os.path.join(self.tmp, "run")
        role = os.path.join(run, "ov")
        for sub in ("lower", "upper", "work", "mer\nged"):
            os.makedirs(os.path.join(role, sub), mode=0o700)
        os.chmod(run, 0o700)
        os.chmod(role, 0o700)
        with open(os.path.join(role, "lower", "shared.txt"),
                  "w") as handle:
            handle.write("lower-original\n")
        target = os.path.join(role, "mer\nged")
        # S81-round5: binding canary, planted in upper
        # (LF name tests escape, the canary itself stays
        # plain and off argv).
        canary = "lf-canary-%d" % os.getpid()
        with open(os.path.join(
                role, "upper",
                provision.MOUNT_CANARY_NAME), "w") as handle:
            handle.write(canary)
        tdev, tino = self._helper_ids(target)
        argv = [sys.executable, provision.__file__,
               "mount-fs", *self._run_root_argv(run),
               "--target", target,
               "--target-dev", tdev, "--target-ino", tino,
               "--fstype", "overlay"]
        for name in ("lower", "upper", "work"):
            dev, ino = self._helper_ids(
                os.path.join(role, name))
            argv += ["--layer",
                    f"{name}={role}/{name}:{dev}:{ino}"]
        mounted = False
        verified_mnt_id = None
        try:
            mnt = sudo(*argv)
            # S93-round5: arm mount custody from the LIVE table,
            # not the report: a helper that mounts and then fails
            # verification still leaves an effect to retire.
            if mount_live_at(target):
                mounted = True
            self.assertEqual(mnt.returncode, 0,
                             mnt.stdout + mnt.stderr)
            self.assertNotIn("\n", mnt.stdout.strip("\n"),
                             "report must stay one frame")
            line = mnt.stdout.splitlines()[0]
            mnt_id, source, super_opts = self._parse_mounted_line(
                line, target)
            self.assertEqual(source, "overlay")
            table = provision.read_mount_table()
            rows = provision.find_mounts(table, target)
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["mnt_id"], mnt_id)
            verified_mnt_id = rows[0]["mnt_id"]
            # S17-round5: through the live overlay (in-ns).
            self.assertEqual(
                ns_text(os.path.join(target, "shared.txt")),
                "lower-original\n")
            row = rows[0]
            bye = sudo(sys.executable, provision.__file__,
                       "retire-mount",
                       "--run-root", run, "--target", target,
                       "--fstype", row["fstype"],
                       "--source", row["source"],
                       "--mnt-id", str(row["mnt_id"]),
                       "--mount-root", row["root"])
            self.assertEqual(bye.returncode, 0,
                             bye.stdout + bye.stderr)
            # Discharge only after CONFIRMED retirement: the
            # live row must be gone, not merely reported gone.
            if not mount_live_at(target):
                mounted = False
        finally:
            if mounted:
                retire_verified_mount(target, verified_mnt_id)

    # S102-round6 live effect check: unprivileged and refused
    # entries never touch keeper infrastructure. A PRIVATE
    # keeper is ensured and killed first (S117: the shared
    # keeper is never killed); real default create, legacy
    # inspect and an invalid create then run THROUGH THE
    # PRIVATE (stale) keeper paths (S137: injected into the
    # actual subprocess interpreters, so an erroneous ensure
    # can no longer silently reuse the healthy shared
    # keeper) — both pidfile records stay byte-identical, no
    # new keeper sleep appears, and the commands still report
    # their own outcomes. The shared keeper is re-verified
    # for later tests before returning.
    def test_live_unprivileged_entries_spawn_no_keeper(self):
        # S117: the dead-keeper precondition uses a PRIVATE
        # keeper this test exclusively owns — the shared
        # per-UID keeper is never killed. S137: the entry
        # subprocesses run through the redirected tool with
        # the private stale paths injected (proven by the
        # in-test probe below), so the no-spawn proof keeps
        # its discriminating precondition; the shared keeper
        # is verified alive, byte-identical and recoverable
        # afterward.
        global_pidfile, _ = provision._keeper_paths()
        with open(global_pidfile, "rb") as handle:
            global_before = handle.read()
        global_identity = provision._MOUNT_NS_IDENTITY
        self.assertIsNotNone(global_identity)

        def sleepers():
            out = subprocess.run(
                ["pgrep", "-f", "^sleep infinity$"],
                capture_output=True, text=True)
            return {int(word) for word in out.stdout.split()
                    if word.isdigit()}

        quiesce_unproven = []
        replacement_adopted = False
        with private_keeper_state(self.tmp) as (pidfile,
                                               priv_candir):
            handles_before = len(provision._KEEPERS)
            provision.ensure_mount_ns()
            # S131: registered immediately, before every
            # fallible observation below.
            lives = []
            # R10-009: re-snapshotted after the bound kill,
            # before the entries run; R12-010: tri-state (bytes,
            # None never-existed, UNREADABLE) so an unreadable
            # entry never proves nothingness.
            stale = None
            keeper_pid, keeper_start = register_keeper_life(
                lives)
            try:
                # S116: PIDFD-authority kill bound to the
                # originally verified starttime.
                kill_bound_keeper(keeper_pid, keeper_start)
                self.assertTrue(
                    poll_proc_gone(keeper_pid),
                    "private keeper survived SIGKILL")
                try:
                    provision._KEEPERS[
                        handles_before].wait(timeout=30)
                except subprocess.TimeoutExpired:
                    self.fail("private keeper tree did not "
                              "collapse after the bound kill")
                stale = snapshot_entry_record(pidfile)
                before = sleepers()
                # S137: the private stale paths go into the
                # ACTUAL subprocess interpreters — the probe
                # proves the precondition (these entries
                # consult the dead private keeper, never the
                # healthy shared one), then the real entries
                # run through the same redirection.
                tool = write_redirected_tool(self.tmp)
                env = private_keeper_subprocess_env(
                    pidfile, priv_candir)
                probe = subprocess.run(
                    [sys.executable, tool,
                     "--probe-keeper-paths"],
                    capture_output=True, text=True,
                    timeout=60, env=env)
                self.assertEqual(probe.returncode, 0,
                                 probe.stdout + probe.stderr)
                self.assertEqual(
                    json.loads(probe.stdout),
                    [pidfile, priv_candir])
                run = os.path.join(self.tmp, "plain")
                manifest = os.path.join(self.tmp, "plain.json")
                first = subprocess.run(
                    [sys.executable, tool, "create",
                     "--manifest", manifest, "--run-root", run],
                    capture_output=True, text=True, timeout=300,
                    env=env)
                self.assertEqual(first.returncode, 0,
                                 first.stdout + first.stderr)
                second = subprocess.run(
                    [sys.executable, tool, "inspect",
                     "--manifest", manifest, "--run-root", run],
                    capture_output=True, text=True, timeout=300,
                    env=env)
                self.assertEqual(second.returncode, 0,
                                 second.stdout + second.stderr)
                third = subprocess.run(
                    [sys.executable, tool, "create",
                     "--manifest", manifest, "--run-root",
                     "/etc/shadow"],
                    capture_output=True, text=True, timeout=120,
                    env=env)
                self.assertEqual(third.returncode, 2,
                                 third.stdout + third.stderr)
                # No keeper infrastructure appeared: neither
                # the private stale record nor the shared
                # record changed, and no new sleeper exists.
                try:
                    with open(pidfile, "rb") as handle:
                        now = handle.read()
                except OSError:
                    now = None
                self.assertEqual(now, stale)
                with open(global_pidfile, "rb") as handle:
                    self.assertEqual(handle.read(), global_before)
                self.assertTrue(sleepers() <= before)
            finally:
                # R10-009: a fixtured entry that erroneously
                # spawned replaced the private record — adopt
                # the unaccounted replacement into lives so
                # the quiesce retires it instead of leaking an
                # unrecorded keeper, and retain the fixture.
                replacement_adopted = \
                    adopt_recorded_replacement(
                        pidfile, stale, lives)
                quiesce_unproven = quiesce_private_lives(lives)
                if quiesce_unproven or replacement_adopted:
                    # S131: retirement unproven — retain the
                    # ORIGINAL private records/dirs for manual
                    # recovery instead of letting tearDown
                    # erase them.
                    self._retain_tmp = True
                    sys.stderr.write(
                        "UNPROVEN private lives "
                        f"{quiesce_unproven!r} "
                        f"(adopted={replacement_adopted}); "
                        f"original fixture {self.tmp} "
                        "retained\n")
        # The shared keeper this suite (and any other fixture)
        # depends on is untouched and recoverable: the cache
        # was dropped, so this re-ensure fully re-verifies
        # link + canary before routing again.
        provision.ensure_mount_ns()
        with open(global_pidfile, "rb") as handle:
            self.assertEqual(handle.read(), global_before)
        self.assertEqual(provision._MOUNT_NS_IDENTITY,
                         global_identity)
        rows = provision.read_mount_table()
        self.assertIsInstance(rows, list)
        if quiesce_unproven or replacement_adopted:
            self.fail(
                "private keeper lives not proven retired: "
                f"{quiesce_unproven!r} "
                f"(adopted={replacement_adopted}; original "
                f"fixture retained at {self.tmp})")

    # S100/S103-round6 live: killing the keeper drops every
    # later routing decision loudly, and the next ensure
    # respawns exactly one verified keeper (new identity,
    # canary present, routed reads work) — no dual keepers,
    # no silent adoption of the stale record.
    def test_live_keeper_respawn_recovers(self):
        # S116/S117: the kill runs through PIDFD authority
        # bound to the originally verified starttime, against
        # a PRIVATE keeper this test exclusively owns — the
        # shared per-UID keeper survives with its record and
        # identity intact, and routed reads through it still
        # work afterward.
        global_pidfile, _ = provision._keeper_paths()
        with open(global_pidfile, "rb") as handle:
            global_before = handle.read()
        global_identity = provision._MOUNT_NS_IDENTITY
        self.assertIsNotNone(global_identity)
        quiesce_unproven = []
        with private_keeper_state(self.tmp) as (pidfile, _candir):
            handles_before = len(provision._KEEPERS)
            provision.ensure_mount_ns()
            # S131: registered immediately, before every
            # fallible observation below.
            lives = []
            old_pid, old_start = register_keeper_life(lives)
            try:
                with open(pidfile, "rb") as handle:
                    old = handle.read().split()
                self.assertEqual(int(old[0]), old_pid)
                # S116 live replacement-task negative: a wrong
                # starttime refuses — signum 0, harmless even
                # if the refusal regressed — and the recorded
                # life survives.
                self.assertEqual(
                    provision._keeper_starttime(old_pid),
                    old_start)
                pin = provision.pin_proc(old_pid)
                try:
                    with self.assertRaises(
                            provision.AdmissionError):
                        provision.signal_owned(
                            old_pid, 0, pin, old_start + 1)
                finally:
                    os.close(pin)
                self.assertEqual(
                    provision._keeper_starttime(old_pid),
                    old_start)
                # The bound kill retires exactly this life.
                kill_bound_keeper(old_pid, old_start)
                self.assertTrue(
                    poll_proc_gone(old_pid),
                    "private keeper survived SIGKILL")
                try:
                    provision._KEEPERS[
                        handles_before].wait(timeout=30)
                except subprocess.TimeoutExpired:
                    self.fail("private keeper tree did not "
                              "collapse after the bound kill")
                # Routed decisions on the stale cache refuse
                # loudly.
                with self.assertRaises(provision.AdmissionError):
                    provision.read_mount_table()
                # The next ensure respawns + verifies a fresh
                # keeper.
                provision._MOUNT_NS = None
                provision._MOUNT_NS_IDENTITY = None
                nspath = provision.ensure_mount_ns()
                # S131: the replacement life is registered
                # IMMEDIATELY — before the fallible
                # pidfile/table reads below — so a failure
                # between still reaches the finalizer instead
                # of escaping with a live keeper.
                early_pid, early_start = register_keeper_life(
                    lives)
                with open(pidfile, "rb") as handle:
                    new = handle.read().split()
                new_pid = int(new[0])
                self.assertNotEqual(new_pid, old_pid)
                self.assertEqual(
                    nspath, f"/proc/{new_pid}/ns/mnt")
                rows = provision.read_mount_table()
                self.assertIsInstance(rows, list)
                self.assertFalse(os.path.exists(
                    f"/proc/{old_pid}"))
                # Retire the respawned private keeper inside
                # the private state — no leaked root sleepers,
                # no pinned namespace.
                _, _, new_start, _ = \
                    provision._MOUNT_NS_IDENTITY
                # The immediately registered life is the
                # observed one (single registration, no late
                # append to forget).
                self.assertEqual((new_pid, new_start),
                                 (early_pid, early_start))
                self.assertEqual(
                    provision._keeper_starttime(new_pid),
                    new_start)
                kill_bound_keeper(new_pid, new_start)
                self.assertTrue(
                    poll_proc_gone(new_pid),
                    "respawned private keeper survived SIGKILL")
                try:
                    provision._KEEPERS[
                        handles_before + 1].wait(timeout=30)
                except subprocess.TimeoutExpired:
                    self.fail("respawned private keeper tree "
                              "did not collapse after the "
                              "bound kill")
            finally:
                quiesce_unproven = quiesce_private_lives(lives)
                if quiesce_unproven:
                    # S131: retirement unproven — retain the
                    # ORIGINAL private records/dirs for manual
                    # recovery instead of letting tearDown
                    # erase them.
                    self._retain_tmp = True
                    sys.stderr.write(
                        "UNPROVEN private lives "
                        f"{quiesce_unproven!r}; original "
                        f"fixture {self.tmp} retained\n")
        # The independent shared keeper is untouched and
        # recoverable: same record, same life, routed reads
        # work after a full re-verification.
        provision.ensure_mount_ns()
        with open(global_pidfile, "rb") as handle:
            self.assertEqual(handle.read(), global_before)
        self.assertEqual(provision._MOUNT_NS_IDENTITY,
                         global_identity)
        rows = provision.read_mount_table()
        self.assertIsInstance(rows, list)
        if quiesce_unproven:
            self.fail(
                "private keeper lives not proven retired: "
                f"{quiesce_unproven!r} (original fixture "
                f"retained at {self.tmp})")

    # S99-round6 end to end: real privileged create, inspect
    # and cleanup through the production entry points (main,
    # including the in-namespace re-exec), with independent
    # device/mount correspondence — files stat onto their
    # mounts (not the covered parents), the loop still binds
    # the image, the host table stays clean, and cleanup
    # discharges everything. The ext4 arms adapt when loop
    # support is unavailable (skip recorded, overlay still
    # fully verified).
    def test_live_privileged_create_inspect_cleanup_e2e(self):
        tool = provision.__file__
        run = os.path.join(self.tmp, "run")
        manifest = os.path.join(self.tmp, "manifest.json")

        def tool_run(*args, timeout=600):
            return subprocess.run(
                [sys.executable, tool, *args],
                capture_output=True, text=True,
                timeout=timeout)

        def ns_stat(path):
            out = sudo(sys.executable, "-c",
                       "import os, sys\n"
                       f"st = os.stat({path!r})\n"
                       "print(st.st_dev, st.st_ino)")
            self.assertEqual(out.returncode, 0,
                             out.stdout + out.stderr)
            dev, ino = out.stdout.split()
            return (int(dev), int(ino))

        # S118: retirement is armed BEFORE creation —
        # create runs INSIDE the try, so every outcome (a
        # failed create, a timeout, a mid-body assertion)
        # still reaches production cleanup in the finally
        # below.
        try:
            created = tool_run(
                "create", "--manifest", manifest,
                "--run-root", run, "--privileged")
            self.assertEqual(created.returncode, 0,
                             created.stdout + created.stderr)
            with open(manifest) as handle:
                doc = json.load(handle)
            # The manifest binds the keeper it provisioned in.
            mode = doc.get("mount_ns")
            self.assertIsInstance(mode, dict)
            pidfile, _ = provision._keeper_paths()
            with open(pidfile) as handle:
                recorded = handle.read().split()
            self.assertEqual(
                (mode["pid"], mode["nsid"]),
                (int(recorded[0]), int(recorded[1])))
            mounts = {entry["target"]: entry
                      for entry in doc.get("mounts", [])}
            # Overlay correspondence (always available): the
            # shared file stats onto the mount, which differs
            # from the covered parent — three channels agree
            # (manifest row, ns table, in-ns stat).
            overseen = [target for target in mounts
                        if target.endswith("/merged")]
            self.assertGreaterEqual(len(overseen), 1)
            table = provision.read_mount_table()
            with open("/proc/self/mountinfo") as handle:
                host = handle.read()
            for target in overseen:
                self.assertNotIn(target, host)
                rows = provision.find_mounts(table, target)
                self.assertEqual(len(rows), 1)
                self.assertEqual(
                    rows[0]["mnt_id"],
                    mounts[target]["mnt_id"])
                parent = os.path.dirname(target)
                file_dev, _ = ns_stat(os.path.join(
                    target, "shared.txt"))
                mnt_dev, _ = ns_stat(target)
                parent_dev, _ = ns_stat(parent)
                self.assertEqual(file_dev, mnt_dev)
                self.assertNotEqual(mnt_dev, parent_dev)
            # Ext4 correspondence when loop provisioned it:
            # exactly one loop device backs our image (sysfs
            # scan — no manifest strings), and the mount's
            # device numbers name that loop (major 7).
            ext4_mnt = os.path.join(run, "ext4", "mnt")
            if ext4_mnt in mounts:
                import glob
                import re
                images = glob.glob(
                    os.path.join(run, "ext4", "*.img"))
                self.assertEqual(len(images), 1)
                image = images[0]
                ours = []
                for path in glob.glob(
                        "/sys/block/loop*/loop/backing_file"):
                    try:
                        with open(path) as handle:
                            content = handle.read().strip()
                    except OSError:
                        continue
                    if content == image:
                        ours.append(path)
                self.assertEqual(len(ours), 1)
                loopnum = int(
                    re.search(r"loop(\d+)", ours[0]).group(1))
                file_dev, _ = ns_stat(
                    os.path.join(ext4_mnt, "a.bin"))
                mnt_dev, _ = ns_stat(ext4_mnt)
                parent_dev, _ = ns_stat(
                    os.path.join(run, "ext4"))
                self.assertEqual(file_dev, mnt_dev)
                self.assertNotEqual(mnt_dev, parent_dev)
                self.assertEqual(os.major(mnt_dev), 7)
                self.assertEqual(os.minor(mnt_dev), loopnum)
            else:
                # G1-I3: the ext4 arm must not be silently
                # optional — on a loop+mkfs-capable host a
                # missing arm is breakage, not a pass.
                # S113: probe the capability production
                # actually uses (native loop-control ioctl),
                # not the losetup utility's health.
                loop_probe = sudo(
                    sys.executable, "-c", NATIVE_LOOP_PROBE)
                have_loop = native_loop_probe_verdict(
                    loop_probe.returncode, loop_probe.stdout)
                have_mkfs = (
                    shutil.which("mkfs.ext4") is not None)
                verdict = ext4_arm_verdict(
                    False, have_loop, have_mkfs)
                if verdict == "required":
                    self.fail(
                        "ext4 arm missing on a loop-capable "
                        "host (FS01 cell: "
                        f"{doc.get('cells', {}).get('FS01')!r})")
                self.assertIn("FS01", doc.get("cells", {}))
                reason = doc["cells"]["FS01"].get("reason", "")
                self.assertTrue(
                    fs01_skip_reason_ok(reason),
                    "FS01 skip names no missing capability: "
                    f"{reason!r}")
            # Churn's driver (a raw-Popen child of
            # create) was born inside the keeper namespace —
            # its bind mounts land in-ns by inheritance.
            drivers = [
                proc for proc in doc.get("procs", [])
                if proc.get("role") == "churn-driver"
                and os.path.exists(f"/proc/{proc['pid']}")]
            self.assertGreaterEqual(len(drivers), 1)
            link = sudo(
                "readlink",
                f"/proc/{drivers[0]['pid']}/ns/mnt")
            self.assertEqual(link.returncode, 0,
                             link.stdout + link.stderr)
            self.assertEqual(link.stdout.strip(),
                             f"mnt:[{mode['nsid']}]")
            # Provisioned procs are independently alive.
            for proc in doc.get("procs", [])[:4]:
                self.assertTrue(
                    os.path.exists(f"/proc/{proc['pid']}"),
                    proc)
            inspected = tool_run(
                "inspect", "--manifest", manifest,
                "--run-root", run)
            self.assertEqual(inspected.returncode, 0,
                             inspected.stdout +
                             inspected.stderr)
            self.assertIn("admitted", inspected.stdout)
        finally:
            # S118: production cleanup runs on EVERY path —
            # including a failed create and mid-body timeouts.
            # Its own failure (or a raised timeout) preserves
            # the manifest + fixture root OUTSIDE the tearDown
            # rmtree instead of erasing recovery custody, and
            # fails loudly.
            try:
                cleaned = tool_run(
                    "cleanup", "--manifest", manifest,
                    "--run-root", run)
            except Exception as exc:
                cleaned = None
                cleanup_note = f"cleanup raised {exc!r}"
            else:
                cleanup_note = (
                    f"cleanup rc={cleaned.returncode} "
                    f"out={cleaned.stdout.strip()[-300:]} "
                    f"err={cleaned.stderr.strip()[-300:]}")
            cleanup_ok = (cleaned is not None
                          and cleaned.returncode == 0)
            try:
                table = provision.read_mount_table()
                leftovers = [
                    row for row in table
                    if row["target"].startswith(run + "/")]
                with open("/proc/self/mountinfo") as handle:
                    host = handle.read()
                host_clean = (run + "/" not in host)
                observe_note = ""
            except Exception as exc:
                leftovers = None
                host_clean = False
                observe_note = (
                    f"residue unobservable: {exc!r}")
            # R10-010: the fixture root itself is verdict
            # residue — observed once so the verdict and the
            # assertion below agree by construction. R11-010:
            # only proven absence counts; an unstatable root
            # reports surviving (preserve + loud failure).
            root_gone = fixture_root_gone(run)
            verdict = e2e_retirement_verdict(
                cleanup_ok, leftovers, host_clean, root_gone)
            # S130: removal of the ORIGINAL fixture is
            # conditional on proven retirement — copies
            # alone (new inodes, original paths in the
            # manifest) cannot recover, and removing the
            # original image can make loop retirement
            # refuse its deleted backing.
            self._retain_tmp = e2e_retirement_retains_tmp(
                verdict)
            preserved = None
            if verdict != "retired":
                preserved = preserve_e2e_evidence(
                    run, manifest,
                    f"{cleanup_note} "
                    f"leftovers={leftovers!r} "
                    f"host_clean={host_clean} "
                    f"root_gone={root_gone} {observe_note}")
            self.assertTrue(
                cleanup_ok,
                f"{cleanup_note} (evidence: {preserved})")
            self.assertTrue(
                root_gone,
                f"fixture root {run} survives cleanup "
                f"(evidence: {preserved})")
            self.assertEqual(leftovers, [], observe_note)
            self.assertTrue(
                host_clean,
                "host table shows fixture residue under "
                f"{run}/")


@unittest.skipUnless(live_mounts_enabled(),
                     "TT04_LIVE_MOUNTS=1 and sudo -n required")
class LiveProcTests(unittest.TestCase):
    # S22-round4 live: the full EPERM-to-escalation chain. A
    # root-owned sleep grandchild is pinnable by the
    # controller (descendant) but unsignallable (uid
    # mismatch — the direct pidfd signal provably returns
    # EPERM), so signal_owned escalates through the
    # re-pinning signal-proc helper and the process dies by
    # real effect. (The no-numeric-kill mechanism is pinned
    # unprivileged by
    # test_signal_owned_uses_pidfd_not_numeric, where os.kill
    # is rigged to explode.)
    def test_live_signal_escalates_and_kills_root_proc(self):
        import errno as _errno
        import signal as _signal
        if os.geteuid() == 0:
            self.skipTest("needs a non-root controller")
        runner = None
        victim = None
        try:
            runner = subprocess.Popen(
                ["sudo", "-n", "sleep", "117"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL)
            victim = self._poll_sudo_child(runner.pid, 10)
            self.assertEqual(
                os.stat(f"/proc/{victim}").st_uid, 0)
            pin = provision.pin_proc(victim)
            try:
                # The escalation trigger is real, not mocked.
                self.assertEqual(
                    provision._pidfd_send_signal(pin, 0),
                    _errno.EPERM)
                _, start = provision.stat_state_start(victim)
                self.assertTrue(provision.signal_owned(
                    victim, _signal.SIGTERM, pin, start))
            finally:
                os.close(pin)
            self.assertTrue(
                self._poll_gone(victim, 10),
                "root sleep survived the escalation")
            runner.wait(timeout=30)
        finally:
            # S92-round5: retire ONLY owned tasks through
            # retained authorities — no host-wide pkill, no
            # numeric kill. The root victim (if the test failed
            # before killing it) is re-pinned and re-verified
            # by identity, then signaled through the
            # escalation helper; a reused number refuses
            # (AdmissionError) instead of signaling a
            # stranger. The sudo runner is our own child,
            # killed through the retained Popen handle
            # (unreaped while held — the number cannot be
            # recycled underneath).
            if victim is not None:
                try:
                    signal_verified_proc(
                        victim, _signal.SIGKILL)
                except (provision.ProcAbsent,
                        provision.ProcUnknown,
                        provision.AdmissionError):
                    pass
                if not self._poll_gone(victim, 10):
                    sys.stderr.write(
                        "WARNING: owned victim %d survived "
                        "S92 cleanup\n" % victim)
            if runner is not None and runner.poll() is None:
                runner.kill()
                runner.wait(timeout=30)

    @staticmethod
    def _poll_sudo_child(sudo_pid, timeout):
        deadline = time.time() + timeout
        path = f"/proc/{sudo_pid}/task/{sudo_pid}/children"
        while time.time() < deadline:
            try:
                with open(path) as handle:
                    kids = handle.read().split()
            except OSError:
                kids = []
            if kids:
                return int(kids[0])
            time.sleep(0.1)
        raise AssertionError("sudo child never appeared")

    @staticmethod
    def _poll_gone(pid, timeout):
        deadline = time.time() + timeout
        while time.time() < deadline:
            if not os.path.exists(f"/proc/{pid}"):
                return True
            time.sleep(0.1)
        return False


class MountCustodyTests(unittest.TestCase):
    # S93-round5: the mount-custody state machine, without
    # privilege. The live table and sudo are scripted; no mount,
    # namespace, or sudo is touched. Ungated: these run in the
    # default suite, while the live classes above skip without
    # TT04_LIVE_MOUNTS=1.
    def _row(self, mnt_id):
        return {"mnt_id": mnt_id, "source": "overlay",
                "fstype": "overlay", "root": "/"}

    def test_retire_attempts_when_unverified_and_live(self):
        from unittest import mock
        with mock.patch(__name__ + ".sudo") as sudo_mock, \
             mock.patch(__name__ + ".mount_live_at",
                        return_value=[self._row(41)]):
            self.assertTrue(
                retire_verified_mount("/t", None))
        sudo_mock.assert_called_once_with("umount", "/t")

    def test_retire_skips_when_absent(self):
        from unittest import mock
        with mock.patch(__name__ + ".sudo") as sudo_mock, \
             mock.patch(__name__ + ".mount_live_at",
                        return_value=[]):
            self.assertFalse(
                retire_verified_mount("/t", 41))
        sudo_mock.assert_not_called()

    def test_retire_attempts_when_id_matches(self):
        from unittest import mock
        with mock.patch(__name__ + ".sudo") as sudo_mock, \
             mock.patch(__name__ + ".mount_live_at",
                        return_value=[self._row(41)]):
            self.assertTrue(
                retire_verified_mount("/t", 41))
        sudo_mock.assert_called_once_with("umount", "/t")

    def test_retire_skips_foreign_replacement(self):
        from unittest import mock
        with mock.patch(__name__ + ".sudo") as sudo_mock, \
             mock.patch(__name__ + ".mount_live_at",
                        return_value=[self._row(99)]):
            self.assertFalse(
                retire_verified_mount("/t", 41))
        sudo_mock.assert_not_called()

    def test_retire_attempts_when_table_unreadable(self):
        from unittest import mock
        with mock.patch(__name__ + ".sudo") as sudo_mock, \
             mock.patch(__name__ + ".mount_live_at",
                        side_effect=OSError("ns gone")):
            self.assertTrue(
                retire_verified_mount("/t", 41))
        sudo_mock.assert_called_once_with("umount", "/t")


class ProcCustodyTests(unittest.TestCase):
    # S92-round5: the owned-proc retirement helper, without
    # privilege. Pin/stat/signal/close are scripted; no task is
    # touched. Ungated like MountCustodyTests above.
    def test_signal_sends_through_fresh_pin(self):
        from unittest import mock
        with mock.patch.object(
                provision, "pin_proc",
                return_value=7) as pin_mock, \
             mock.patch.object(
                provision, "stat_state_start",
                return_value=("S", 1234)), \
             mock.patch.object(
                provision, "signal_owned",
                return_value=True) as signal_mock, \
             mock.patch("os.close") as close_mock:
            self.assertTrue(signal_verified_proc(4242, 9))
        pin_mock.assert_called_once_with(4242)
        signal_mock.assert_called_once_with(4242, 9, 7, 1234)
        close_mock.assert_called_once_with(7)

    def test_signal_reports_gone_at_signal(self):
        from unittest import mock
        with mock.patch.object(
                provision, "pin_proc",
                return_value=7), \
             mock.patch.object(
                provision, "stat_state_start",
                return_value=("S", 1234)), \
             mock.patch.object(
                provision, "signal_owned",
                return_value=False), \
             mock.patch("os.close") as close_mock:
            self.assertFalse(signal_verified_proc(4242, 9))
        close_mock.assert_called_once_with(7)

    def test_signal_propagates_absent_without_close(self):
        from unittest import mock
        with mock.patch.object(
                provision, "pin_proc",
                side_effect=provision.ProcAbsent("gone")), \
             mock.patch("os.close") as close_mock:
            with self.assertRaises(provision.ProcAbsent):
                signal_verified_proc(4242, 9)
        close_mock.assert_not_called()

    def test_signal_closes_pin_on_identity_refusal(self):
        from unittest import mock
        with mock.patch.object(
                provision, "pin_proc",
                return_value=7), \
             mock.patch.object(
                provision, "stat_state_start",
                return_value=("S", 1234)), \
             mock.patch.object(
                provision, "signal_owned",
                side_effect=provision.AdmissionError(
                    "changed")), \
             mock.patch("os.close") as close_mock:
            with self.assertRaises(provision.AdmissionError):
                signal_verified_proc(4242, 9)
        close_mock.assert_called_once_with(7)

    def test_signal_closes_pin_on_stat_failure(self):
        from unittest import mock
        with mock.patch.object(
                provision, "pin_proc",
                return_value=7), \
             mock.patch.object(
                provision, "stat_state_start",
                side_effect=provision.ProcAbsent("gone")), \
             mock.patch("os.close") as close_mock:
            with self.assertRaises(provision.ProcAbsent):
                signal_verified_proc(4242, 9)
        close_mock.assert_called_once_with(7)


class KeeperSignalTests(unittest.TestCase):
    # S116: keeper kills go through PIDFD authority bound to
    # the ORIGINALLY verified starttime — never a numeric
    # root kill of a pidfile number. Pin/stat/signal/close
    # are scripted; no task is touched. Ungated like
    # ProcCustodyTests above.
    def test_kill_sends_through_pidfd_with_original_start(self):
        import signal as _signal
        from unittest import mock
        with mock.patch.object(
                provision, "pin_proc",
                return_value=7) as pin_mock, \
             mock.patch.object(
                provision, "signal_owned",
                return_value=True) as signal_mock, \
             mock.patch("os.close") as close_mock, \
             mock.patch("os.kill",
                        side_effect=AssertionError(
                            "numeric kill used")), \
             mock.patch(__name__ + ".sudo",
                        side_effect=AssertionError(
                            "sudo kill used")):
            self.assertTrue(kill_bound_keeper(4242, 1234))
        pin_mock.assert_called_once_with(4242)
        # The ORIGINAL starttime travels into the
        # identity-verified signal (and its EPERM
        # escalation) — a recycled number refuses.
        signal_mock.assert_called_once_with(
            4242, _signal.SIGKILL, 7, 1234)
        close_mock.assert_called_once_with(7)

    def test_kill_replacement_refusal_propagates_and_closes(self):
        # S116 replacement-task negative: the pinned number
        # now hosts another life — signal_owned refuses, the
        # refusal propagates, the pin still closes, and no
        # numeric kill is attempted as a fallback.
        from unittest import mock
        with mock.patch.object(
                provision, "pin_proc",
                return_value=7), \
             mock.patch.object(
                provision, "signal_owned",
                side_effect=provision.AdmissionError(
                    "starttime changed")), \
             mock.patch("os.close") as close_mock, \
             mock.patch("os.kill",
                        side_effect=AssertionError(
                            "numeric kill used")), \
             mock.patch(__name__ + ".sudo",
                        side_effect=AssertionError(
                            "sudo kill used")):
            with self.assertRaises(provision.AdmissionError):
                kill_bound_keeper(4242, 1234)
        close_mock.assert_called_once_with(7)

    def test_kill_reports_gone_without_close(self):
        from unittest import mock
        with mock.patch.object(
                provision, "pin_proc",
                side_effect=provision.ProcAbsent("gone")), \
             mock.patch("os.close") as close_mock:
            with self.assertRaises(provision.ProcAbsent):
                kill_bound_keeper(4242, 1234)
        close_mock.assert_not_called()

    # R12-009: stat_state_start must answer ProcUnknown (not
    # ProcAbsent) for a hidepid-hidden live task — invisible
    # ENOENT is unobservable, never proven gone (else
    # signal_owned returns False and the finalizer silently
    # discharges a live keeper). Real live pid (self); only
    # the /proc read is hidden, kill stays the proof channel.
    def test_hidden_live_stat_answers_unknown_not_absent(self):
        from unittest import mock
        me = os.getpid()
        real_open = open

        def hide_proc(path, *args, **kwargs):
            if str(path).startswith("/proc/"):
                raise FileNotFoundError(
                    2, "hidepid-style invisible-ENOENT")
            return real_open(path, *args, **kwargs)

        with mock.patch("builtins.open", side_effect=hide_proc):
            self.assertIsNone(os.kill(me, 0))
            with self.assertRaises(provision.ProcUnknown):
                provision.stat_state_start(me)

    # R12-009 twin: a truly gone number still answers ProcAbsent
    # (kill-ESRCH proves death) — the hidepid guard must not
    # swallow genuine absence into unknown.
    def test_gone_stat_still_absent(self):
        with self.assertRaises(provision.ProcAbsent):
            provision.stat_state_start(2 ** 30 - 1)


def hostile_cover_argv(fake, pidfile):
    """sudo unshare argv that bind-covers grep in a private ns. (R10-001)

    R11-011: both paths are shlex.quote()d — they live under
    TemporaryDirectory(), which honors TMPDIR, so spaces must
    not break the fixture and shell metacharacters in a
    hostile TMPDIR must not execute as root. ``$$`` stays
    unquoted: it is the fixture shell's own pid by design.
    """
    return ["sudo", "-n", "unshare", "-m", "sh", "-c",
            "mount --make-rprivate / && "
            f"mount --bind {shlex.quote(fake)} /usr/bin/grep && "
            f"echo $$ > {shlex.quote(pidfile)} && exec sleep 120"]


def retire_proven_hostile_victim(victim, victim_start,
                                 cover_proven):
    """SIGKILL the hostile victim only on proven cover. (R12-011)

    ``cover_proven`` must be True only after the fixture's
    mountinfo cover was OBSERVED on the sampled number: a
    sample taken after the original's death verifies BY
    CONSTRUCTION against its own replacement, so killing on
    an unproven sample is tautological authentication
    (R11-012's mismatch-refusal protects pre-reuse samples
    only). Unproven cover skips the kill loudly and never
    raises — like retire_hostile_victim, which this
    delegates to once proven.
    """
    if not cover_proven:
        sys.stderr.write(
            "WARNING: hostile victim %r not signaled: fixture "
            "cover never proven (sample unauthenticated)\n"
            % (victim,))
        return
    retire_hostile_victim(victim, victim_start)


def retire_hostile_victim(victim, victim_start):
    """SIGKILL the hostile-cover victim through PIDFD authority. (R11-012)

    kill_bound_keeper against the starttime retained at
    observation: exit or PID reuse before finalization refuses
    (never redirects a root-authorized signal at whoever holds
    the number now). Gone/refused/unknown all swallow — the
    victim is a 120 s sleeper, so a missed kill is transient
    and the finally must not mask test errors — but refusals
    warn loudly (S131 spirit). Never raises.
    """
    if victim is None or victim_start is None:
        return
    try:
        kill_bound_keeper(victim, victim_start)
    except (provision.ProcAbsent, provision.AdmissionError,
            provision.ProcUnknown) as exc:
        sys.stderr.write(
            "WARNING: hostile victim %d not signaled: %r\n"
            % (victim, exc))


class RetireHostileVictimTests(unittest.TestCase):
    # R11-012, ungated: own-uid sleepers never hit the EPERM
    # escalation, so no sudo is needed. The kill path only sees
    # (number, expected_start) — a live process under a
    # mismatched starttime IS the reuse shape, deterministically.
    def _sleeper(self):
        proc = subprocess.Popen(
            ["sleep", "120"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.addCleanup(proc.wait)
        self.addCleanup(proc.kill)
        return proc

    def test_bound_life_is_signaled(self):
        proc = self._sleeper()
        _, start = provision.stat_state_start(proc.pid)
        retire_hostile_victim(proc.pid, start)
        # Reap, don't poll: the signal is sent synchronously
        # but death lands asynchronously.
        self.assertEqual(proc.wait(timeout=10), -9)

    def test_exited_victim_swallowed(self):
        from unittest import mock
        proc = self._sleeper()
        _, start = provision.stat_state_start(proc.pid)
        proc.kill()
        proc.wait()
        with mock.patch("sys.stderr") as err:
            retire_hostile_victim(proc.pid, start)
        self.assertIn("not signaled", err.write.call_args[0][0])

    def test_reused_number_not_signaled(self):
        # The finding's regression: finalization after the
        # original life is gone and its number means another
        # life must refuse — no signal to the replacement.
        from unittest import mock
        proc = self._sleeper()
        _, real = provision.stat_state_start(proc.pid)
        with mock.patch("sys.stderr") as err:
            retire_hostile_victim(proc.pid, real + 1)
        # No-signal first, under a grace: death lands
        # asynchronously, so a bare poll lets a numeric kill
        # slip through. A SIGKILLed process is reaped well
        # inside a second; a refused one is still alive.
        try:
            proc.wait(timeout=1)
        except subprocess.TimeoutExpired:
            pass
        else:
            self.fail("replacement was signaled")
        self.assertIn("not signaled", err.write.call_args[0][0])

    def test_unproven_cover_leaves_fresh_sample_unsignaled(self):
        # R12-011: cover never proven + a freshly sampled
        # holder (the tautology shape: the sample postdates
        # the original's death and verifies BY CONSTRUCTION)
        # must not signal — the substitute survives the
        # complete fixture finalization. R11-012's
        # mismatch-refusal only protects pre-reuse samples.
        from unittest import mock
        proc = self._sleeper()
        _, fresh = provision.stat_state_start(proc.pid)
        with mock.patch("sys.stderr"):
            retire_proven_hostile_victim(
                proc.pid, fresh, cover_proven=False)
        try:
            proc.wait(timeout=1)
        except subprocess.TimeoutExpired:
            pass
        else:
            self.fail("substitute was signaled")

    def test_proven_cover_still_retires(self):
        # R12-011 anti-overcorrection twin: proven cover
        # delegates to the bound kill — the fixture victim
        # still retires through PIDFD authority.
        proc = self._sleeper()
        _, start = provision.stat_state_start(proc.pid)
        retire_proven_hostile_victim(
            proc.pid, start, cover_proven=True)
        self.assertEqual(proc.wait(timeout=10), -9)


class HostileCoverArgvTests(unittest.TestCase):
    # R11-011, ungated by design: the cover body is a pure
    # string function of its paths, so stub mount/sleep on PATH
    # prove the parsing (literal words, no substitution)
    # without privilege or namespaces.
    def test_evil_tmpdir_parses_literally(self):
        base = tempfile.mkdtemp(prefix="evil-cover-")
        self.addCleanup(shutil.rmtree, base, ignore_errors=True)
        marker = os.path.join(base, "PWNED")
        evil = os.path.join(
            base, "a b", "c$(touch " + marker + ")d")
        os.makedirs(evil)
        bindir = os.path.join(base, "bin")
        os.makedirs(bindir)
        argv_log = os.path.join(base, "argv.log")
        for name in ("mount", "sleep"):
            stub = os.path.join(bindir, name)
            with open(stub, "w") as handle:
                handle.write(
                    "#!/bin/sh\n"
                    "{\n"
                    f"printf '{name}:';\n"
                    "printf '<%s>' \"$@\";\n"
                    "printf '\\n';\n"
                    f"}} >> {shlex.quote(argv_log)}\n")
            os.chmod(stub, 0o755)
        fake = os.path.join(evil, "grep")
        with open(fake, "w") as handle:
            handle.write("x\n")
        pidfile = os.path.join(evil, "victim.pid")
        body = hostile_cover_argv(fake, pidfile)[-1]
        proc = subprocess.run(
            ["sh", "-c", body],
            capture_output=True, text=True,
            env={**os.environ,
                 "PATH": bindir + ":/usr/bin:/bin"},
            timeout=30)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        # No substitution executed...
        self.assertFalse(os.path.exists(marker))
        # ...the bind saw ONE literal source path...
        with open(argv_log) as handle:
            log = handle.read()
        self.assertIn(
            f"mount:<--bind><{fake}></usr/bin/grep>", log)
        # ...and the redirection landed literally — with the
        # shell's own pid, so $$ survived quoting by design.
        with open(pidfile) as handle:
            content = handle.read().strip()
        self.assertTrue(content.isdigit())


@unittest.skipUnless(live_mounts_enabled(),
                     "needs TT04_LIVE_MOUNTS=1 + passwordless sudo")
class HostileNsCanaryTests(unittest.TestCase):
    # R10-001: a hostile mount namespace ships a covered grep
    # that always exits 0. Pre-fix the gate joined the
    # candidate ns and trusted that grep (True = wrong); the
    # anchored gate never joins and reads the candidate's
    # mountinfo host-side, which lacks our canary (False).
    # The interception probe below fails loudly if the
    # fixture ever stops covering grep — the refusal must
    # never pass vacuously.
    def test_covered_grep_cannot_authenticate_hostile_ns(self):
        canary = "ab" * 16
        with tempfile.TemporaryDirectory() as tmp:
            fake = os.path.join(tmp, "grep")
            with open(fake, "w") as handle:
                handle.write("#!/bin/sh\necho HOSTILE-GREP-COVERED\nexit 0\n")
            os.chmod(fake, 0o755)
            pidfile = os.path.join(tmp, "victim.pid")
            runner = subprocess.Popen(
                hostile_cover_argv(fake, pidfile),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL)
            try:
                deadline = time.time() + 15
                victim = None
                victim_start = None
                cover_proven = False
                while time.time() < deadline:
                    try:
                        with open(pidfile) as handle:
                            victim = int(handle.read().strip())
                        # R11-012: retain the birth identity for
                        # the bound final kill — same /proc
                        # readability domain as the mountinfo
                        # open that already gates readiness.
                        _, victim_start = \
                            provision.stat_state_start(victim)
                        with open(f"/proc/{victim}/mountinfo") as handle:
                            if "/usr/bin/grep" in handle.read():
                                # R12-011: cover OBSERVED on the
                                # sampled number — the sample is
                                # fixture-bound from here.
                                cover_proven = True
                                break
                    except (OSError, ValueError, provision.ProcAbsent,
                            provision.ProcUnknown):
                        pass
                    time.sleep(0.1)
                self.assertIsNotNone(
                    victim, "hostile fixture never published its pid")
                with open(f"/proc/{victim}/mountinfo") as handle:
                    hostile_mounts = handle.read()
                self.assertIn("/usr/bin/grep", hostile_mounts)
                self.assertNotIn(f"canary-{canary}", hostile_mounts)
                probe = subprocess.run(
                    ["sudo", "-n", "nsenter",
                     f"--mount=/proc/{victim}/ns/mnt",
                     "/usr/bin/grep", "anything", "/dev/null"],
                    capture_output=True, text=True, timeout=30)
                self.assertIn(
                    "HOSTILE-GREP-COVERED", probe.stdout,
                    "hostile fixture must intercept joined grep")
                nslink = subprocess.run(
                    ["sudo", "-n", "readlink",
                     f"/proc/{victim}/ns/mnt"],
                    capture_output=True, text=True, timeout=30)
                self.assertEqual(nslink.returncode, 0)
                nsid = int(nslink.stdout.strip()[5:-1])
                self.assertFalse(
                    provision._ns_has_canary_pinned(
                        victim, nsid, canary))
            finally:
                # R11-012: PIDFD-authority kill against the
                # retained starttime — exit or reuse before
                # finalization refuses (loudly) instead of
                # redirecting root SIGKILL by number. R12-011:
                # gated on proven cover — a sample taken after
                # the original's death would verify by
                # construction against its replacement.
                retire_proven_hostile_victim(
                    victim, victim_start, cover_proven)
                try:
                    runner.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    runner.kill()
                    runner.wait(timeout=15)


class PrivateKeeperStateTests(unittest.TestCase):
    # S117: the redirection mechanics pin without privilege
    # (no ensure, no keeper spawned). The live destructive
    # tests run their real kill/respawn lifecycle inside it.
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="keeper-state-pin-")
        self.addCleanup(shutil.rmtree, self.tmp,
                        ignore_errors=True)
        self.saved = (provision._keeper_paths,
                      provision._MOUNT_NS,
                      provision._MOUNT_NS_IDENTITY)

    def tearDown(self):
        (provision._keeper_paths, provision._MOUNT_NS,
         provision._MOUNT_NS_IDENTITY) = self.saved

    def test_private_paths_redirect_and_restore(self):
        provision._MOUNT_NS = "SENTINEL-NS"
        provision._MOUNT_NS_IDENTITY = ("SENT-ID",)
        with private_keeper_state(self.tmp) as (pidfile, candir):
            self.assertTrue(pidfile.startswith(self.tmp))
            self.assertTrue(candir.startswith(self.tmp))
            self.assertEqual(provision._keeper_paths(),
                             (pidfile, candir))
            # No identity crosses the boundary inward.
            self.assertIsNone(provision._MOUNT_NS)
            self.assertIsNone(provision._MOUNT_NS_IDENTITY)
        # Restoration is exact, and the cache stays cleared:
        # the shared keeper must be re-verified, never
        # resumed from a pre-destruction snapshot.
        self.assertIs(provision._keeper_paths, self.saved[0])
        self.assertIsNone(provision._MOUNT_NS)
        self.assertIsNone(provision._MOUNT_NS_IDENTITY)
        pidfile, _ = provision._keeper_paths()
        self.assertEqual(
            pidfile, f"/tmp/scopebase-mntns-{os.geteuid()}.pid")

    def test_exception_inside_still_restores(self):
        with self.assertRaises(RuntimeError):
            with private_keeper_state(self.tmp):
                raise RuntimeError("mid-test failure")
        self.assertIs(provision._keeper_paths, self.saved[0])
        self.assertIsNone(provision._MOUNT_NS)
        self.assertIsNone(provision._MOUNT_NS_IDENTITY)


class PollGoneTests(unittest.TestCase):
    # S117: the /proc-gone poll, pinned without privilege.
    def test_gone_immediately(self):
        self.assertTrue(poll_proc_gone(2 ** 30 - 1, timeout=5))

    def test_persistent_reports_false(self):
        self.assertFalse(
            poll_proc_gone(os.getpid(), timeout=0))

    # R10-008: only ENOENT counts as gone — an entry that
    # cannot be stated (EACCES: alive but unobservable)
    # answers present, never retired.
    def test_unstatable_answers_present(self):
        from unittest import mock
        real_stat = os.stat

        def deny_proc(path, *args, **kwargs):
            if str(path).startswith("/proc/"):
                raise PermissionError(13, "hidepid-style denial")
            return real_stat(path, *args, **kwargs)

        with mock.patch("os.stat", side_effect=deny_proc):
            self.assertFalse(poll_proc_gone(4242, timeout=0))

    # R12-009: hidepid=2 returns ENOENT for hidden LIVE tasks —
    # the gone-poll must require kill-proven death (R11-001),
    # never ENOENT alone. Real live pid (self); only /proc is
    # hidden, kill stays the independent existence proof.
    def test_invisible_enoent_answers_present(self):
        from unittest import mock
        me = os.getpid()
        real_stat = os.stat

        def hide_proc(path, *args, **kwargs):
            if str(path).startswith("/proc/"):
                raise FileNotFoundError(
                    2, "hidepid-style invisible-ENOENT")
            return real_stat(path, *args, **kwargs)

        with mock.patch("os.stat", side_effect=hide_proc):
            # Independent proof through the hide: kill bypasses
            # /proc visibility (unpatched) — we are alive.
            self.assertIsNone(os.kill(me, 0))
            self.assertFalse(poll_proc_gone(me, timeout=0))


class QuiesceLivesTests(unittest.TestCase):
    # S117: mid-test-failure retirement of exclusively owned
    # private keeper lives — signaled ONLY while the number
    # still hosts the recorded life. Scripted; nothing is
    # touched. Ungated.
    def test_alive_life_is_retired(self):
        from unittest import mock
        with mock.patch.object(
                provision, "_keeper_starttime",
                return_value=1234) as start_mock, \
             mock.patch(__name__ + ".kill_bound_keeper",
                        return_value=True) as kill_mock, \
             mock.patch(__name__ + ".poll_proc_gone",
                        return_value=True) as gone_mock:
            # S131: proven retirement returns no unproven lives.
            self.assertEqual(
                quiesce_private_lives([(4242, 1234)]), [])
        start_mock.assert_called_once_with(4242)
        kill_mock.assert_called_once_with(4242, 1234)
        gone_mock.assert_called_once_with(4242, timeout=15)

    def test_recycled_number_untouched(self):
        # Proven-foreign (a recycled int starttime) is left
        # alone, never signaled. The None (unknown) half of
        # the old combined test asserted silent discharge —
        # the R11-006 bug — and is superseded: None-gone
        # retires silently while None-present answers unproven
        # (see the R11-006 twins below).
        from unittest import mock
        with mock.patch.object(
                provision, "_keeper_starttime",
                return_value=9999), \
             mock.patch(__name__ + ".kill_bound_keeper") \
                as kill_mock:
            self.assertEqual(
                quiesce_private_lives([(4242, 1234)]), [])
        kill_mock.assert_not_called()

    def test_gap_exit_classifies_retired_without_signaling(self):
        # R10-014: the life exits between the starttime
        # observation and pin acquisition — pin_proc raises
        # ProcAbsent (proven absence; kill_bound_keeper's own
        # contract pins the propagation) and the quiesce must
        # classify retired: no unproven entry, no signal sent,
        # no disappearance poll.
        from unittest import mock
        with mock.patch.object(
                provision, "_keeper_starttime",
                return_value=1234), \
             mock.patch.object(
                provision, "pin_proc",
                side_effect=provision.ProcAbsent("gone")), \
             mock.patch.object(
                provision, "signal_owned") as signal_mock, \
             mock.patch(__name__ + ".poll_proc_gone") \
                as gone_mock:
            self.assertEqual(
                quiesce_private_lives([(4242, 1234)]), [])
        signal_mock.assert_not_called()
        gone_mock.assert_not_called()

    def test_kill_error_warns_and_never_raises(self):
        import io
        from unittest import mock
        captured = io.StringIO()
        with mock.patch.object(
                provision, "_keeper_starttime",
                return_value=1234), \
             mock.patch(__name__ + ".kill_bound_keeper",
                        side_effect=OSError("boom")), \
             mock.patch("sys.stderr", captured):
            # S131: the fault is RETURNED (callers retain the
            # private records/dirs and fail loudly) — never a
            # warning-only pass over a live keeper.
            unproven = quiesce_private_lives([(4242, 1234)])
        self.assertIn("4242", captured.getvalue())
        self.assertEqual(len(unproven), 1)
        self.assertEqual(unproven[0][:2], (4242, 1234))
        self.assertTrue(unproven[0][2])

    def test_survivor_reported_unproven(self):
        # S131: the signal went out but the life is still
        # there — retirement unproven, reported for manual
        # recovery, never silently dropped.
        import io
        from unittest import mock
        captured = io.StringIO()
        with mock.patch.object(
                provision, "_keeper_starttime",
                return_value=1234), \
             mock.patch(__name__ + ".kill_bound_keeper",
                        return_value=True), \
             mock.patch(__name__ + ".poll_proc_gone",
                        return_value=False), \
             mock.patch("sys.stderr", captured):
            unproven = quiesce_private_lives([(4242, 1234)])
        self.assertIn("4242", captured.getvalue())
        self.assertEqual(len(unproven), 1)
        self.assertEqual(unproven[0][:2], (4242, 1234))

    def test_gone_between_check_and_signal_counts_retired(self):
        # signal_owned reports the life already gone (False):
        # retired, not unproven.
        from unittest import mock
        with mock.patch.object(
                provision, "_keeper_starttime",
                return_value=1234), \
             mock.patch(__name__ + ".kill_bound_keeper",
                        return_value=False) as kill_mock, \
             mock.patch(__name__ + ".poll_proc_gone") \
                as gone_mock:
            self.assertEqual(
                quiesce_private_lives([(4242, 1234)]), [])
        kill_mock.assert_called_once_with(4242, 1234)
        gone_mock.assert_not_called()

    def test_gone_state_unreadable_reported_unproven(self):
        # R10-008: the signal went out but gone-state cannot
        # be stated (EACCES) — unproven retirement with the
        # records retained, never a quiet pass.
        import io
        from unittest import mock
        real_stat = os.stat

        def deny_proc(path, *args, **kwargs):
            if str(path) == "/proc/4242":
                raise PermissionError(13, "hidepid-style denial")
            return real_stat(path, *args, **kwargs)

        captured = io.StringIO()
        with mock.patch.object(
                provision, "_keeper_starttime",
                return_value=1234), \
             mock.patch(__name__ + ".kill_bound_keeper",
                        return_value=True), \
             mock.patch("os.stat", side_effect=deny_proc), \
             mock.patch("sys.stderr", captured):
            unproven = quiesce_private_lives(
                [(4242, 1234)], timeout=0)
        self.assertIn("4242", captured.getvalue())
        self.assertEqual(len(unproven), 1)
        self.assertEqual(unproven[0][:2], (4242, 1234))

    def test_starttime_error_returns_unproven_and_never_raises(self):
        # S131: unreadable state is unproven custody, not a
        # cleanup crash (pre-fix the exception propagated out
        # of the "never raises" finalizer).
        import io
        from unittest import mock
        captured = io.StringIO()
        with mock.patch.object(
                provision, "_keeper_starttime",
                side_effect=OSError("proc gone mid-read")), \
             mock.patch(__name__ + ".kill_bound_keeper") \
                as kill_mock, \
             mock.patch("sys.stderr", captured):
            unproven = quiesce_private_lives([(4242, 1234)])
        kill_mock.assert_not_called()
        self.assertIn("4242", captured.getvalue())
        self.assertEqual(len(unproven), 1)
        self.assertEqual(unproven[0][:2], (4242, 1234))

    def test_unreadable_starttime_live_life_reported_unproven(self):
        # R11-006: the life is LIVE but its stat is unreadable
        # (hidepid-style denial) — the REAL reader returns
        # None, and quiesce must report unproven (never
        # silently discharge), never signal, and the non-empty
        # return retains the original dir via the caller's
        # S131 _retain_tmp wiring. Only the underlying open
        # fails; _keeper_starttime itself is unpatched.
        import io
        from unittest import mock
        sleeper = subprocess.Popen(
            ["sleep", "30"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.addCleanup(sleeper.wait)
        self.addCleanup(sleeper.kill)
        start = provision._keeper_starttime(sleeper.pid)
        self.assertIsNotNone(
            start, "precondition: sleeper live and readable")
        real_open = open

        def deny_stat(path, *args, **kwargs):
            if str(path) == f"/proc/{sleeper.pid}/stat":
                raise PermissionError(13, "hidepid-style denial")
            return real_open(path, *args, **kwargs)

        captured = io.StringIO()
        with mock.patch("builtins.open",
                        side_effect=deny_stat), \
             mock.patch("sys.stderr", captured):
            unproven = quiesce_private_lives(
                [(sleeper.pid, start)])
        self.assertIsNone(
            sleeper.poll(), "quiesce must not signal the life")
        self.assertEqual(len(unproven), 1)
        self.assertEqual(unproven[0][:2], (sleeper.pid, start))
        self.assertIn(str(sleeper.pid), captured.getvalue())

    def test_gone_life_with_none_starttime_retires_silently(self):
        # R11-006 twin (anti-overcorrection): None that the
        # hardened poll proves ENOENT-gone still retires
        # silently — only present-but-unobservable answers
        # unproven.
        from unittest import mock
        with mock.patch.object(
                provision, "_keeper_starttime",
                return_value=None), \
             mock.patch(__name__ + ".poll_proc_gone",
                        return_value=True) as gone_mock, \
             mock.patch(__name__ + ".kill_bound_keeper") \
                as kill_mock:
            self.assertEqual(
                quiesce_private_lives([(4242, 1234)]), [])
        gone_mock.assert_called_once_with(4242, timeout=0)
        kill_mock.assert_not_called()

    def test_hidden_live_keeper_is_unproven_and_unsignaled(self):
        # R12-009: the life is LIVE but hidepid=2 hides it with
        # invisible-ENOENT (not denial) at BOTH layers — the
        # REAL starttime reader returns None and the REAL poll
        # stats ENOENT. Quiesce must report unproven (unresolved
        # custody), never signal, and the non-empty return
        # retains records via the caller's S131 wiring. kill
        # stays unpatched as the independent existence proof
        # (hidepid affects only /proc visibility).
        import io
        from unittest import mock
        sleeper = subprocess.Popen(
            ["sleep", "30"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.addCleanup(sleeper.wait)
        self.addCleanup(sleeper.kill)
        start = provision._keeper_starttime(sleeper.pid)
        self.assertIsNotNone(
            start, "precondition: sleeper live and readable")
        real_open = open
        real_stat = os.stat

        def hide_proc_open(path, *args, **kwargs):
            if str(path).startswith("/proc/"):
                raise FileNotFoundError(
                    2, "hidepid-style invisible-ENOENT")
            return real_open(path, *args, **kwargs)

        def hide_proc_stat(path, *args, **kwargs):
            if str(path).startswith("/proc/"):
                raise FileNotFoundError(
                    2, "hidepid-style invisible-ENOENT")
            return real_stat(path, *args, **kwargs)

        captured = io.StringIO()
        with mock.patch("builtins.open",
                        side_effect=hide_proc_open), \
             mock.patch("os.stat",
                        side_effect=hide_proc_stat), \
             mock.patch("sys.stderr", captured):
            # Independent existence proof through the hide.
            self.assertIsNone(os.kill(sleeper.pid, 0))
            unproven = quiesce_private_lives(
                [(sleeper.pid, start)])
        self.assertIsNone(
            sleeper.poll(), "quiesce must not signal the life")
        self.assertEqual(len(unproven), 1)
        self.assertEqual(unproven[0][:2], (sleeper.pid, start))
        self.assertIn("unreadable but present", unproven[0][2])
        self.assertIn(str(sleeper.pid), captured.getvalue())


class AdoptReplacementTests(unittest.TestCase):
    # R10-009: an entry that erroneously spawns replaces the
    # private record — the finalizer must adopt the
    # replacement into lives (never leak an unrecorded root
    # keeper) and flag the fixture retained. Never raises.
    def test_adopt_refuses_namespace_mismatch(self):
        # R11-007: a changed record pointing at an unrelated
        # controlled process (ordinary sleeper, fictitious
        # namespace/canary) must NOT be adopted — sampling
        # the current holder's starttime grants quiescence
        # authority over whoever holds the number, which a
        # recycled replacement turns into a stranger kill.
        # Refusal retains (True: unresolved custody) while
        # the sleeper survives quiescence. (Supersedes the
        # old test_adopt_appends_live_replacement, which
        # asserted adoption of this exact stranger shape.)
        sleeper = subprocess.Popen(
            ["sleep", "120"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.addCleanup(sleeper.wait)
        self.addCleanup(sleeper.kill)
        with tempfile.TemporaryDirectory() as tmp:
            pidfile = os.path.join(tmp, "ns.pid")
            with open(pidfile, "wb") as handle:
                handle.write(
                    f"{sleeper.pid} 77 {'cd' * 16}\n".encode())
            lives = []
            self.assertTrue(
                adopt_recorded_replacement(
                    pidfile, b"stale-bytes", lives))
            # Quiesce BEFORE asserting: pre-fix the adopted
            # stranger is killed here (the finding's
            # consequence — only the kill is asserted first
            # so the RED output shows it); post-fix there is
            # nothing to quiesce and the sleeper survives.
            # timeout=0 fails the failure mode fast (a sent
            # signal over a test-owned child would otherwise
            # stall 15s on its unreaped zombie, correctly
            # reported unproven — quiesce signals, the
            # spawner reaps). The settle lets a wrongly sent
            # SIGKILL land before the survival assert, so the
            # RED output shows the stranger-kill, not a
            # death-window pass.
            unproven = quiesce_private_lives(lives, timeout=0)
            time.sleep(0.5)
            self.assertIsNone(
                sleeper.poll(), "refused stranger must survive")
            self.assertEqual(lives, [])
            self.assertEqual(unproven, [])

    @unittest.skipUnless(shutil.which("unshare"),
                         "needs unshare for a real mountns")
    def test_adopt_appends_namespace_matching_replacement(self):
        # R11-007 twin (anti-overcorrection): a holder that
        # genuinely runs the RECORDED namespace is adopted —
        # the R10-009 rescue (an erroneously spawned real
        # keeper) keeps working. Real namespaces via
        # unprivileged `unshare -rm`; the canary stays
        # fictitious (adoption binds the namespace, not the
        # mount secret — see the adopter docstring).
        # R12-012: capability-gated spawn (skips explicitly
        # when user namespaces are denied).
        sleeper = spawn_real_mountns_sleeper()
        self.addCleanup(sleeper.wait)
        self.addCleanup(sleeper.kill)
        own_ns = os.readlink("/proc/self/ns/mnt")
        deadline = time.time() + 5
        while True:
            kid_ns = os.readlink(f"/proc/{sleeper.pid}/ns/mnt")
            if kid_ns != own_ns:
                break
            self.assertLess(
                time.time(), deadline,
                "unshare never left our namespace")
            time.sleep(0.02)
        nsid = int(kid_ns[5:-1])
        with tempfile.TemporaryDirectory() as tmp:
            pidfile = os.path.join(tmp, "ns.pid")
            with open(pidfile, "wb") as handle:
                handle.write(
                    f"{sleeper.pid} {nsid} {'cd' * 16}\n".encode())
            lives = [(4242, 1234)]
            self.assertTrue(
                adopt_recorded_replacement(
                    pidfile, b"stale-bytes", lives))
            bound = provision._keeper_starttime(sleeper.pid)
            self.assertIsNotNone(bound)
            self.assertEqual(
                lives, [(4242, 1234), (sleeper.pid, bound)])

    def test_userns_probe_classifies_tool_and_capability(self):
        # R12-012: tool presence never implies capability —
        # sysctl, LSM, or container policy may deny
        # user-namespace creation with unshare installed. The
        # probe answers False for a missing tool, a refused
        # unshare, or a spawn failure; True only for a clean
        # `unshare -rm true`.
        from unittest import mock
        with mock.patch("shutil.which", return_value=None):
            self.assertFalse(userns_unshare_available())
        with mock.patch("shutil.which",
                        return_value="/fake/unshare"), \
             mock.patch("subprocess.run") as run_mock:
            run_mock.return_value.returncode = 1
            self.assertFalse(userns_unshare_available())
            run_mock.return_value.returncode = 0
            self.assertTrue(userns_unshare_available())
            run_mock.side_effect = OSError(1, "denied")
            self.assertFalse(userns_unshare_available())

    def test_denied_userns_skips_with_capability_message(self):
        # R12-012: unshare installed but user namespaces
        # denied must SKIP with an explicit capability
        # message — never run discovery into an unexpected
        # setup error (dead-child readlink raise or a 5 s
        # never-left-namespace failure).
        from unittest import mock
        with mock.patch("shutil.which",
                        return_value="/fake/unshare"), \
             mock.patch("subprocess.run") as run_mock:
            run_mock.return_value.returncode = 1
            with self.assertRaisesRegex(
                    unittest.SkipTest, "user namespaces"):
                spawn_real_mountns_sleeper()

    def test_unchanged_record_noop(self):
        with tempfile.TemporaryDirectory() as tmp:
            pidfile = os.path.join(tmp, "ns.pid")
            with open(pidfile, "wb") as handle:
                handle.write(b"4321 77 %s\n" % (b"cd" * 16))
            lives = [(4242, 1234)]
            with open(pidfile, "rb") as handle:
                stale = handle.read()
            self.assertFalse(
                adopt_recorded_replacement(pidfile, stale, lives))
            self.assertEqual(lives, [(4242, 1234)])

    def test_missing_pidfile_noop_when_nothing_ensured(self):
        with tempfile.TemporaryDirectory() as tmp:
            lives = []
            self.assertFalse(
                adopt_recorded_replacement(
                    os.path.join(tmp, "gone.pid"), None, lives))
            self.assertEqual(lives, [])

    def test_missing_pidfile_after_stale_retains(self):
        # R11-008: a record that existed at entry but is gone
        # at finalization is suspicious, not a noop — the
        # fixture must be retained for manual recovery.
        with tempfile.TemporaryDirectory() as tmp:
            lives = []
            self.assertTrue(
                adopt_recorded_replacement(
                    os.path.join(tmp, "gone.pid"), b"stale",
                    lives))
            self.assertEqual(lives, [])

    def test_unreadable_entry_snapshot_classified(self):
        # R12-010: the entry snapshot is tri-state — record
        # bytes, None (never existed), or the UNREADABLE
        # sentinel (any non-missing read error). Collapsing
        # unreadable into None lets entry+final read failures
        # around an erroneous spawn discharge custody silently.
        # The denial is mocked (deterministic as any uid —
        # chmod denial needs non-root); missing/present are real.
        from unittest import mock
        with tempfile.TemporaryDirectory() as tmp:
            pidfile = os.path.join(tmp, "ns.pid")
            with open(pidfile, "wb") as handle:
                handle.write(b"4321 77 %s\n" % (b"cd" * 16))
            self.assertEqual(
                snapshot_entry_record(pidfile),
                b"4321 77 %s\n" % (b"cd" * 16))
            os.unlink(pidfile)
            self.assertIsNone(snapshot_entry_record(pidfile))
            with open(pidfile, "wb") as handle:
                handle.write(b"4321 77 %s\n" % (b"cd" * 16))
            real_open = open

            def deny_proc(path, *args, **kwargs):
                if str(path) == pidfile:
                    raise PermissionError(13, "denied")
                return real_open(path, *args, **kwargs)

            with mock.patch("builtins.open",
                            side_effect=deny_proc):
                self.assertIs(
                    snapshot_entry_record(pidfile),
                    _ENTRY_SNAPSHOT_UNREADABLE)

    def test_unreadable_entry_snapshot_retains_on_final_failure(
            self):
        # R12-010: entry unreadable (sentinel) + final read
        # failure retains (True) — entry failure never proves
        # never-existed, so teardown keeps recovery custody for
        # a replacement the finalizer never saw.
        with tempfile.TemporaryDirectory() as tmp:
            lives = []
            self.assertTrue(
                adopt_recorded_replacement(
                    os.path.join(tmp, "gone.pid"),
                    _ENTRY_SNAPSHOT_UNREADABLE, lives))
            self.assertEqual(lives, [])

    def test_appeared_record_with_no_stale_adopts(self):
        # R11-008 mirror: stale None but a record exists now
        # (a replacement published where nothing was
        # ensured) — changed-record path, adopted + retained.
        with tempfile.TemporaryDirectory() as tmp:
            pidfile = os.path.join(tmp, "ns.pid")
            with open(pidfile, "wb") as handle:
                handle.write(b"not-a-record")
            lives = []
            self.assertTrue(
                adopt_recorded_replacement(
                    pidfile, None, lives))
            self.assertEqual(lives, [])

    def test_fifo_record_refuses_bounded(self):
        # R11-009: a FIFO at the pidfile must refuse under a
        # deadline — a blocking open would hang the finalizer
        # before quiescence or retention. Retention flags
        # (True); the original lives are untouched so
        # finalization continues over them. R12-013: runs in
        # a reaped child process (independently enforceable
        # termination — a restored unbounded read is
        # SIGKILLed at the bound, never wedging the shared
        # interpreter past the assertion).
        with tempfile.TemporaryDirectory() as tmp:
            pidfile = os.path.join(tmp, "ns.pid")
            os.mkfifo(pidfile)
            lives = [(4242, 1234)]

            def read_record():
                return (adopt_recorded_replacement(
                    pidfile, b"stale", lives), list(lives))

            finished, payload, exitcode = run_bounded_reader_case(
                read_record, timeout=10)
            self.assertTrue(
                finished, "adopter blocked on a FIFO record")
            self.assertEqual(exitcode, 0)
            result, child_lives = payload
            self.assertEqual(result, True)
            self.assertEqual(child_lives, [(4242, 1234)])

    @unittest.skipUnless(os.path.exists("/dev/zero"),
                         "needs /dev/zero")
    def test_device_record_refuses_bounded(self):
        # R11-009: a symlink to /dev/zero must refuse without
        # reading — an unbounded read never returns. Same
        # retention contract as the FIFO arm. R12-013: reaped
        # child process (a restored unbounded read is
        # SIGKILLed with its address space freed, never
        # allocating inside the shared interpreter).
        with tempfile.TemporaryDirectory() as tmp:
            pidfile = os.path.join(tmp, "ns.pid")
            os.symlink("/dev/zero", pidfile)
            lives = [(4242, 1234)]

            def read_record():
                return (adopt_recorded_replacement(
                    pidfile, b"stale", lives), list(lives))

            finished, payload, exitcode = run_bounded_reader_case(
                read_record, timeout=10)
            self.assertTrue(
                finished,
                "adopter read a device record unbounded")
            self.assertEqual(exitcode, 0)
            result, child_lives = payload
            self.assertEqual(result, True)
            self.assertEqual(child_lives, [(4242, 1234)])

    def test_blocked_reader_terminated_and_reaped(self):
        # R12-013: the known-bad FIFO shape (a blocking open
        # that never returns) run through the bounded runner
        # must FAIL bounded — the worker is SIGKILL-
        # terminated and reaped (independently enforceable
        # termination: threads cannot be killed, processes
        # can), never wedging the shared interpreter.
        with tempfile.TemporaryDirectory() as tmp:
            pidfile = os.path.join(tmp, "ns.pid")
            os.mkfifo(pidfile)

            def hang_forever():
                with open(pidfile, "rb") as handle:
                    handle.read()

            finished, _, exitcode = run_bounded_reader_case(
                hang_forever, timeout=3)
            self.assertFalse(finished)
            self.assertIsNotNone(exitcode, "worker reaped")
            self.assertNotEqual(exitcode, 0)

    @unittest.skipUnless(hasattr(resource, "RLIMIT_AS"),
                         "needs RLIMIT_AS worker budgets")
    def test_worker_budget_respects_inherited_limits(self):
        # R14-013: finite inherited soft AND hard limits — the
        # worker budget must never exceed them. Pre-fix the
        # worker sets (cap, cap) unconditionally: a finite hard
        # limit below the computed cap makes setrlimit fail
        # (unprivileged hard-raise forbidden) so the child
        # reports budget-unset and the reader never runs; a
        # finite soft limit is silently RAISED to the cap,
        # defeating the environment's tighter budget. Post-fix
        # the effective budget is min(computed, soft, hard):
        # ordinary readers execute under both, and allocation
        # hits the inherited budget (not the computed one).
        # Staging is a forked middleman (contained): hard limits
        # cannot be raised back in-process, so the suite process
        # itself must never lower them. The finite limit sits
        # 64MiB above the middleman's VmSize (ordinary readers
        # have headroom; the allocator's reached band excludes
        # both stillborn (0) and unbounded (~512)).
        # R16-013: nearby-hard soft-clamp discrimination — with
        # hard ≈ soft+32MiB the [32,160] band cannot resolve the
        # clamp (unclamped reaches ≈96, still inside). The
        # alloc-report case stages (finite, finite+32MiB) and
        # the worker reports its APPLIED (soft,hard) pair
        # in-child: clamped applies exactly (finite, finite);
        # soft-clamp removal applies (finite+32MiB, finite+32MiB)
        # (or (computed, computed) under a huge fallback hard) —
        # any deviation fails. Vacuous only when the staged hard
        # collapses onto soft (skip, loud).
        import multiprocessing as _mp

        def ordinary_reader():
            return ("ordinary-ok", 42)

        def allocator():
            chunks = []
            reached = 0
            try:
                while True:
                    chunks.append(bytearray(8 * 1024 * 1024))
                    reached += 8
            except MemoryError:
                return ("alloc-capped", reached)

        def middleman(queue, soft, hard, kind):
            # R15-009: adaptive setup — resolve against the
            # inherited hard (never raise it); a skip verdict
            # exits 3 (R14-011 precedent) with the reason
            # best-effort through the queue — the report channel
            # itself may OOM under tight VM (the feeder thread
            # needs stack), so the CODE carries the verdict and
            # os._exit skips teardown roulette.
            inherited_hard = resource.getrlimit(
                resource.RLIMIT_AS)[1]
            verdict, payload = resolve_limit_setup(
                soft, hard, inherited_hard, False)
            if verdict == "skip":
                try:
                    queue.put(("setup-skipped", payload, None))
                    queue.close()
                    queue.join_thread()
                except Exception:
                    pass
                os._exit(3)
            resource.setrlimit(resource.RLIMIT_AS, payload)
            if kind == "ordinary":
                outcome = run_bounded_reader_case(
                    ordinary_reader, timeout=10)
            elif kind == "alloc-report":
                # R16-013: report the worker's APPLIED rlimit
                # in-child (direct contract evidence) plus the
                # staged hard (vacuity gate lives with the
                # parent). The allocator frees its chunks on
                # return, so the report tuple allocates safely
                # past the MemoryError edge.
                staged_hard = payload[1]

                def reporting_allocator():
                    name, reached = allocator()
                    assert name == "alloc-capped", \
                        "R16013 reporting shape broken"
                    applied = resource.getrlimit(
                        resource.RLIMIT_AS)
                    return ("alloc-report", reached, applied,
                            staged_hard)

                outcome = run_bounded_reader_case(
                    reporting_allocator, timeout=30)
            else:
                outcome = run_bounded_reader_case(
                    allocator, timeout=30)
            queue.put(outcome)

        with open("/proc/self/status") as handle:
            vm_kb = None
            for line in handle:
                if line.startswith("VmSize:"):
                    vm_kb = int(line.split()[1])
                    break
        self.assertIsNotNone(vm_kb, "parent VmSize readable")
        finite = (vm_kb // 1024 + 64) * 1024 * 1024
        inf = resource.RLIM_INFINITY
        ctx = _mp.get_context("fork")
        cases = [
            ("hard-ordinary", finite, finite, "ordinary"),
            ("hard-allocator", finite, finite, "allocator"),
            ("soft-ordinary", finite, inf, "ordinary"),
            ("soft-allocator", finite, inf, "allocator"),
            # R16-013: nearby finite hard (soft+32MiB) — the
            # band alone cannot resolve the clamp here.
            ("soft-nearby-hard", finite, finite + 32 * 1024 * 1024,
             "alloc-report"),
        ]
        for tag, soft, hard, kind in cases:
            with self.subTest(tag=tag):
                queue = ctx.Queue()
                middle = ctx.Process(
                    target=middleman,
                    args=(queue, soft, hard, kind))
                middle.start()
                middle.join(90)
                if middle.is_alive():
                    middle.terminate()
                    middle.join(5)
                    if middle.is_alive():
                        middle.kill()
                        middle.join(5)
                self.assertIn(
                    middle.exitcode, (0, 3),
                    "%s: middleman must exit cleanly or skip" % (tag,))
                import queue as _queue
                if middle.exitcode == 3:
                    # Skip verdict: the reason travels best-effort
                    # (get_nowait — the child is dead, so no more
                    # data will ever arrive).
                    try:
                        finished, outcome, _ = queue.get_nowait()
                        reason = (outcome
                                  if finished == "setup-skipped"
                                  else "setup skipped")
                    except _queue.Empty:
                        reason = ("setup skipped (report channel "
                                  "OOMed under tight VM)")
                    self.skipTest(
                        "%s: cannot stage (%s)" % (tag, reason))
                try:
                    finished, outcome, exitcode = queue.get(timeout=10)
                except _queue.Empty:
                    self.fail("%s: middleman must report" % (tag,))
                # Workers reaped on every path (the helper joins;
                # a reaped worker has a collected exitcode).
                self.assertIsNotNone(
                    exitcode, "%s: worker reaped" % (tag,))
                if kind == "ordinary":
                    self.assertTrue(
                        finished,
                        "%s: ordinary reader must execute, got %r"
                        % (tag, outcome))
                    self.assertEqual(exitcode, 0)
                    self.assertEqual(outcome, ("ordinary-ok", 42))
                else:
                    # The allocator catches its own MemoryError and
                    # reports the reached size: finished carries the
                    # ("alloc-capped", MiB) payload, and the band
                    # below proves it hit the INHERITED budget.
                    self.assertTrue(
                        finished,
                        "%s: allocator must report, got %r"
                        % (tag, outcome))
                    self.assertIsNotNone(
                        outcome, "%s: allocator must report" % (tag,))
                    if kind == "alloc-report":
                        kind_out, reached, applied, staged = outcome
                        self.assertEqual(kind_out, "alloc-report")
                        if staged <= finite:
                            self.skipTest(
                                "%s: vacuous (staged hard %r leaves "
                                "no room above soft %r)"
                                % (tag, staged, finite))
                        # R16-013: direct contract evidence — the
                        # worker must apply exactly (finite,
                        # finite); soft-clamp removal applies
                        # (staged-hard, staged-hard) (or
                        # (computed, computed)) instead.
                        self.assertEqual(
                            applied, (finite, finite),
                            "%s: worker applied %r, must clamp to "
                            "(%r, %r)" % (tag, applied, finite, finite))
                    else:
                        kind_out, reached = outcome
                        self.assertEqual(kind_out, "alloc-capped")
                    self.assertGreaterEqual(
                        reached, 32,
                        "%s: allocation stillborn (reached %sMiB)"
                        % (tag, reached))
                    self.assertLessEqual(
                        reached, 160,
                        "%s: allocation missed the inherited budget "
                        "(reached %sMiB)" % (tag, reached))
                    self.assertEqual(exitcode, 0)

    @unittest.skipUnless(hasattr(resource, "RLIMIT_AS"),
                         "needs RLIMIT_AS worker budgets")
    def test_worker_budget_ignores_infinite_inherited_limits(self):
        # IR-006 pin (passes pre- and post-fix — it guards the
        # >= 0 filters, not a behavior change): infinite
        # inherited bounds must not constrain the worker. On
        # -1 platforms (this box: RLIM_INFINITY == -1) the
        # filters skip them; a bare min() would sink the
        # finite computed cap to -1 (unlimited) and run the
        # worker unbounded. The worker reports its applied
        # rlimit through the ordinary reader channel; the
        # applied pair must be (cap, cap) finite. Verified by
        # mutation: with the filters removed the worker
        # reports (-1, -1) and the inequality below fails.
        import multiprocessing as _mp

        def report_rlimit():
            return resource.getrlimit(resource.RLIMIT_AS)

        def middleman(queue):
            inf = resource.RLIM_INFINITY
            # R15-009: infinity is required here (the pin tests
            # infinite inheritance) — skip (exit 3, reason
            # best-effort) when unraisable.
            inherited_hard = resource.getrlimit(
                resource.RLIMIT_AS)[1]
            verdict, payload = resolve_limit_setup(
                inf, inf, inherited_hard, True)
            if verdict == "skip":
                try:
                    queue.put(("setup-skipped", payload, None))
                    queue.close()
                    queue.join_thread()
                except Exception:
                    pass
                os._exit(3)
            resource.setrlimit(resource.RLIMIT_AS, payload)
            outcome = run_bounded_reader_case(
                report_rlimit, timeout=10)
            queue.put(outcome)

        ctx = _mp.get_context("fork")
        queue = ctx.Queue()
        middle = ctx.Process(target=middleman, args=(queue,))
        middle.start()
        middle.join(90)
        if middle.is_alive():
            middle.terminate()
            middle.join(5)
            if middle.is_alive():
                middle.kill()
                middle.join(5)
        self.assertIn(
            middle.exitcode, (0, 3),
            "middleman must exit cleanly or skip")
        import queue as _queue
        if middle.exitcode == 3:
            try:
                finished, outcome, _ = queue.get_nowait()
                reason = (outcome
                          if finished == "setup-skipped"
                          else "setup skipped")
            except _queue.Empty:
                reason = ("setup skipped (report channel "
                          "OOMed under tight VM)")
            self.skipTest(
                "cannot stage infinite inheritance (%s)" % (reason,))
        try:
            finished, outcome, exitcode = queue.get(timeout=10)
        except _queue.Empty:
            self.fail("middleman must report")
        self.assertIsNotNone(exitcode, "worker reaped")
        self.assertTrue(
            finished, "reader must execute, got %r" % (outcome,))
        self.assertEqual(exitcode, 0)
        soft, hard = outcome
        self.assertEqual(
            soft, hard, "applied pair must be (cap, cap)")
        self.assertNotEqual(
            soft, resource.RLIM_INFINITY,
            "infinite inheritance must not leak through as unlimited")
        self.assertGreaterEqual(soft, 512 * 1024 * 1024)

    @unittest.skipUnless(hasattr(resource, "RLIMIT_AS"),
                         "needs RLIMIT_AS worker budgets")
    def test_limit_setup_decision_matrix(self):
        # R15-009: pure decision matrix (no syscalls — the fork
        # test below stages real finite hard). The resolver
        # returns ("apply", (soft, hard)) or ("skip", reason).
        inf = resource.RLIM_INFINITY
        resolve = resolve_limit_setup
        # Specified applicable as-is (nothing raised).
        self.assertEqual(
            resolve(100, 200, 400, False),
            ("apply", (100, 200)))
        self.assertEqual(
            resolve(100, inf, inf, False),
            ("apply", (100, inf)))
        # Infinity unraisable under finite hard: fall back to
        # (finite-soft, inherited-hard).
        self.assertEqual(
            resolve(100, inf, 400, False),
            ("apply", (100, 400)))
        # Case budget exceeds finite hard: explicit skip.
        verdict, reason = resolve(500, inf, 400, False)
        self.assertEqual(verdict, "skip")
        self.assertIn("budget", reason)
        # Infinity required (the pin) but unavailable: skip.
        verdict, reason = resolve(inf, inf, 400, True)
        self.assertEqual(verdict, "skip")
        self.assertIn("infinity", reason)
        # Infinity required and available: apply.
        self.assertEqual(
            resolve(inf, inf, inf, True),
            ("apply", (inf, inf)))
        # Finite raise within hard: apply (soft may rise to
        # hard; only the hard raise is forbidden).
        self.assertEqual(
            resolve(300, 400, 400, False),
            ("apply", (300, 400)))

    @unittest.skipUnless(hasattr(resource, "RLIMIT_AS"),
                         "needs RLIMIT_AS worker budgets")
    def test_limit_setup_under_staged_finite_hard(self):
        # R15-009: fork-based — the CHILD lowers ITS hard to a
        # staged finite value (lowering is always allowed; the
        # suite's own hard is never touched — asserted below),
        # then runs the real setup path (resolve + setrlimit)
        # and reports verdicts.
        import multiprocessing as _mp
        suite_hard = resource.getrlimit(resource.RLIMIT_AS)[1]
        inf = resource.RLIM_INFINITY

        def child(queue):
            # Stage BELOW the inherited hard (never raise it):
            # the suite hard when finite, else 512MiB. The soft
            # budget sits 64MiB above the child's own VmSize
            # (R14-013's formula); when even that exceeds the
            # staged hard the environment is too tight to stage
            # in — report unstageable (the parent skips).
            staged = (suite_hard if suite_hard != inf
                      else 512 * 1024 * 1024)
            resource.setrlimit(resource.RLIMIT_AS, (staged, staged))
            with open("/proc/self/status") as handle:
                vm_kb = None
                for line in handle:
                    if line.startswith("VmSize:"):
                        vm_kb = int(line.split()[1])
                        break
            soft = (vm_kb // 1024 + 64) * 1024 * 1024
            over = staged + 100 * 1024 * 1024
            if soft > staged:
                # Too tight to stage in — skip (exit 3, reason
                # best-effort: the report channel itself may OOM
                # here, so the CODE carries the verdict).
                try:
                    queue.put([("unstageable",
                                "soft %d exceeds staged hard %d"
                                % (soft, staged))])
                    queue.close()
                    queue.join_thread()
                except Exception:
                    pass
                os._exit(3)
            inherited = resource.getrlimit(resource.RLIMIT_AS)
            out = []
            verdict, payload = resolve_limit_setup(
                soft, inf, inherited[1], False)
            out.append(("fallback", verdict, payload, soft, staged))
            if verdict == "apply":
                # Must not raise (the setup path applies it).
                resource.setrlimit(resource.RLIMIT_AS, payload)
                out.append(
                    ("applied", resource.getrlimit(resource.RLIMIT_AS)))
            out.append(
                ("over",) + resolve_limit_setup(
                    over, inf, inherited[1], False))
            out.append(
                ("pin",) + resolve_limit_setup(
                    inf, inf, inherited[1], True))
            try:
                queue.put(out)
            except Exception:
                # Verdicts unreportable under tight VM: skip
                # (cannot prove anything without the report).
                os._exit(3)

        ctx = _mp.get_context("fork")
        queue = ctx.Queue()
        proc = ctx.Process(target=child, args=(queue,))
        proc.start()
        proc.join(60)
        self.assertIn(
            proc.exitcode, (0, 3),
            "setup child must exit cleanly or skip")
        import queue as _queue
        if proc.exitcode == 3:
            try:
                out = queue.get_nowait()
            except _queue.Empty:
                out = [("unstageable", "report channel OOMed")]
            by_tag = {}
            for tag, *rest in out:
                by_tag[tag] = rest
            self.skipTest(
                "suite hard too tight to stage (%s)"
                % (by_tag.get("unstageable", ["no reason"])[0],))
        try:
            out = queue.get(timeout=10)
        except _queue.Empty:
            self.fail("setup child must report")
        by_tag = {}
        for tag, *rest in out:
            by_tag[tag] = rest
        soft = by_tag["fallback"][2]
        staged = by_tag["fallback"][3]
        self.assertEqual(by_tag["fallback"][0], "apply")
        self.assertEqual(by_tag["fallback"][1], (soft, staged))
        self.assertEqual(by_tag["applied"][0], (soft, staged))
        self.assertEqual(by_tag["over"][0], "skip")
        self.assertIn("budget", by_tag["over"][1])
        self.assertEqual(by_tag["pin"][0], "skip")
        self.assertIn("infinity", by_tag["pin"][1])
        # The suite's own hard is untouched by the staging.
        self.assertEqual(
            resource.getrlimit(resource.RLIMIT_AS)[1], suite_hard)

    @unittest.skipUnless(hasattr(resource, "RLIMIT_AS"),
                         "needs RLIMIT_AS worker budgets")
    def test_allocating_reader_contained_outside_interpreter(self):
        # R12-013: the known-bad device shape (an unbounded
        # /dev/zero read) run through the bounded runner must
        # not grow the SUITE interpreter: allocation stays in
        # the child (killed+reaped at the bound) while the
        # parent's RSS barely moves. Threshold: megabytes of
        # real growth vs gigabytes an in-process read adds.
        # R13-011: the child runs under a memory budget, so the
        # worker raises MemoryError and reports it — retirement
        # by budget, proven by the raised payload plus a clean
        # exit (a timeout signal or OOM kill arrives
        # payload-less and nonzero, and fails below).
        import re as _re

        def parent_rss_mb():
            with open("/proc/self/status") as handle:
                for line in handle:
                    match = _re.match(r"VmRSS:\s+(\d+) kB",
                                      line)
                    if match:
                        return int(match.group(1)) // 1024
            raise AssertionError("VmRSS row missing")

        def allocate_forever():
            with open("/dev/zero", "rb") as handle:
                handle.read()

        before = parent_rss_mb()
        finished, outcome, exitcode = run_bounded_reader_case(
            allocate_forever, timeout=3)
        growth = parent_rss_mb() - before
        self.assertFalse(finished)
        self.assertIsNotNone(exitcode, "worker reaped")
        # R13-011: the worker must die BY THE BUDGET (MemoryError
        # raised in-child and reported), not by timeout signal nor
        # OOM kill — both of those arrive without a raised
        # payload, and any nonzero exit previously passed as
        # "contained". A clean exit-0 report excludes signal/OOM
        # death (those are -9/-15, never 0 with a payload).
        self.assertIsNotNone(
            outcome, "worker must report (not die silent by signal/OOM)")
        kind, detail = outcome
        self.assertEqual(kind, "raised")
        self.assertIn(
            "MemoryError", detail,
            "worker must hit its memory budget, got: %s" % (detail,))
        self.assertEqual(
            exitcode, 0,
            "budget-fired worker must report cleanly, not die by signal")
        self.assertLess(
            growth, 1024,
            f"unbounded read leaked into suite RSS (+{growth}MB)")

    def test_symlink_to_regular_reads_through(self):
        # R11-009: the S28 reader resolves symlinks at open —
        # a link to a regular record reads the same bytes
        # (bounded, non-blocking); unchanged content stays a
        # noop. Pins the follow decision deliberately.
        with tempfile.TemporaryDirectory() as tmp:
            target = os.path.join(tmp, "real.pid")
            with open(target, "wb") as handle:
                handle.write(b"4321 77 %s\n" % (b"cd" * 16))
            with open(target, "rb") as handle:
                stale = handle.read()
            pidfile = os.path.join(tmp, "ns.pid")
            os.symlink(target, pidfile)
            lives = [(4242, 1234)]
            self.assertFalse(
                adopt_recorded_replacement(pidfile, stale, lives))
            self.assertEqual(lives, [(4242, 1234)])

    @unittest.skipIf(os.geteuid() == 0,
                         "chmod denial needs non-root "
                         "(as root the read succeeds and the test "
                         "passes via the changed-record path, not "
                         "the OSError arm — covered universally "
                         "by the ENOENT twin)")
    def test_unreadable_record_after_stale_retains(self):
        # R11-008: publish a replacement, deny the finalizer
        # record read — the adopter must flag retention
        # (adopting nothing: no verifiable identity), never
        # silently report "nothing to adopt".
        with tempfile.TemporaryDirectory() as tmp:
            pidfile = os.path.join(tmp, "ns.pid")
            with open(pidfile, "wb") as handle:
                handle.write(b"4321 77 %s\n" % (b"cd" * 16))
            os.chmod(pidfile, 0)
            lives = []
            self.assertTrue(
                adopt_recorded_replacement(
                    pidfile, b"stale", lives))
            self.assertEqual(lives, [])

    def test_malformed_record_retains_without_adopting(self):
        with tempfile.TemporaryDirectory() as tmp:
            pidfile = os.path.join(tmp, "ns.pid")
            with open(pidfile, "wb") as handle:
                handle.write(b"not-a-record")
            lives = []
            self.assertTrue(
                adopt_recorded_replacement(
                    pidfile, b"stale", lives))
            self.assertEqual(lives, [])

    def test_dead_replacement_retains_without_adopting(self):
        with tempfile.TemporaryDirectory() as tmp:
            pidfile = os.path.join(tmp, "ns.pid")
            with open(pidfile, "wb") as handle:
                handle.write(
                    f"{2 ** 30 - 1} 77 {'cd' * 16}\n".encode())
            lives = []
            self.assertTrue(
                adopt_recorded_replacement(
                    pidfile, b"stale", lives))
            self.assertEqual(lives, [])


class RegisterKeeperLifeTests(unittest.TestCase):
    # S131: every acquired keeper is registered with the
    # failure finalizer IMMEDIATELY after ensure, before any
    # fallible observation — a replacement created-then-read
    # must not escape the finalizer when a read between fails.
    # The live respawn test wires this helper into its ensure
    # sites; these pins cover the mechanism itself.
    def setUp(self):
        self.saved = provision._MOUNT_NS_IDENTITY

    def tearDown(self):
        provision._MOUNT_NS_IDENTITY = self.saved

    def test_registers_current_identity(self):
        lives = [(1111, 100)]
        provision._MOUNT_NS_IDENTITY = (4242, 77, 1234, "canary")
        self.assertEqual(register_keeper_life(lives),
                         (4242, 1234))
        self.assertEqual(lives, [(1111, 100), (4242, 1234)])

    def test_no_identity_refuses_loudly(self):
        provision._MOUNT_NS_IDENTITY = None
        with self.assertRaises(AssertionError):
            register_keeper_life([])


class E2ERetirementTests(unittest.TestCase):
    # S118: retirement is complete only when production
    # cleanup succeeded AND no residue remains; anything
    # else preserves the manifest + fixture root outside the
    # tearDown rmtree. Pinned without privilege (real tmpdirs,
    # no mounts); the live E2E wires these decisions into its
    # armed try/finally.
    def test_verdict_matrix(self):
        # R10-010: a surviving fixture root is residue — the
        # false-cleanup-success path (rc 0, clean mounts, root
        # standing) must preserve, never retire.
        self.assertEqual(
            e2e_retirement_verdict(True, [], True, False),
            "preserve")
        self.assertEqual(
            e2e_retirement_verdict(True, [], True, True),
            "retired")
        self.assertEqual(
            e2e_retirement_verdict(False, [], True, True),
            "preserve")
        self.assertEqual(
            e2e_retirement_verdict(
                True, [{"mnt_id": 41}], True, True), "preserve")
        self.assertEqual(
            e2e_retirement_verdict(True, [], False, True),
            "preserve")
        # Unobservable residue is uncertain, never retired.
        self.assertEqual(
            e2e_retirement_verdict(True, None, True, True),
            "preserve")
        self.assertEqual(
            e2e_retirement_verdict(False, None, False, False),
            "preserve")

    def test_preserve_copies_manifest_and_run(self):
        import io
        from unittest import mock
        tmp = tempfile.mkdtemp(prefix="e2e-pin-")
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        run = os.path.join(tmp, "run")
        os.makedirs(os.path.join(run, "ext4"))
        manifest = os.path.join(tmp, "manifest.json")
        with open(manifest, "w") as handle:
            handle.write('{"cells": {}}')
        with open(os.path.join(run, "ext4", "a.bin"),
                  "w") as handle:
            handle.write("payload")
        captured = io.StringIO()
        with mock.patch("sys.stderr", captured):
            dest = preserve_e2e_evidence(
                run, manifest, "cleanup rc=1 for pins")
        self.addCleanup(shutil.rmtree, dest, ignore_errors=True)
        self.assertTrue(os.path.isdir(dest))
        with open(os.path.join(dest, "manifest.json")) as handle:
            self.assertEqual(handle.read(), '{"cells": {}}')
        with open(os.path.join(
                dest, "run", "ext4", "a.bin")) as handle:
            self.assertEqual(handle.read(), "payload")
        with open(os.path.join(dest, "REASON")) as handle:
            self.assertIn("cleanup rc=1", handle.read())
        # Outside the fixture root: the tearDown rmtree of the
        # fixture cannot take it.
        self.assertFalse(dest.startswith(run + os.sep))
        self.assertFalse(dest.startswith(tmp + os.sep))
        self.assertIn("PRESERVED", captured.getvalue())
        self.assertIn(dest, captured.getvalue())

    def test_preserve_survives_missing_run(self):
        import io
        from unittest import mock
        tmp = tempfile.mkdtemp(prefix="e2e-pin-")
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        manifest = os.path.join(tmp, "manifest.json")
        with open(manifest, "w") as handle:
            handle.write('{}')
        captured = io.StringIO()
        with mock.patch("sys.stderr", captured):
            dest = preserve_e2e_evidence(
                os.path.join(tmp, "gone"), manifest,
                "cleanup raised for pins")
        self.addCleanup(shutil.rmtree, dest, ignore_errors=True)
        with open(os.path.join(dest, "manifest.json")) as handle:
            self.assertEqual(handle.read(), "{}")
        self.assertIn("PRESERVED", captured.getvalue())

    def test_root_gone_proven_absence(self):
        # R11-010: only ENOENT counts as removed.
        tmp = tempfile.mkdtemp(prefix="e2e-pin-")
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        self.assertTrue(
            fixture_root_gone(os.path.join(tmp, "run")))

    def test_root_present_reports_surviving(self):
        tmp = tempfile.mkdtemp(prefix="e2e-pin-")
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        run = os.path.join(tmp, "run")
        os.makedirs(run)
        self.assertFalse(fixture_root_gone(run))

    @unittest.skipIf(os.geteuid() == 0,
                         "chmod denial needs non-root "
                         "(as root the stat succeeds and the "
                         "sensitivity assert fails)")
    def test_root_unstatable_reports_surviving(self):
        # R11-010 regression: deny the actual root stat while
        # every other observation appears clean — the verdict
        # must preserve, never retire. Sensitivity: exists()
        # lies here (False despite the present root).
        tmp = tempfile.mkdtemp(prefix="e2e-pin-")
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        run = os.path.join(tmp, "run")
        os.makedirs(run)
        os.chmod(tmp, 0)
        try:
            self.assertFalse(os.path.exists(run))
            self.assertFalse(fixture_root_gone(run))
            self.assertEqual(
                e2e_retirement_verdict(
                    True, [], True, fixture_root_gone(run)),
                "preserve")
        finally:
            os.chmod(tmp, 0o700)

    def test_root_dangling_symlink_reads_gone(self):
        # fixture_root_gone residual, pinned deliberately
        # (first noted under a misnumbered R11-007 entry):
        # the observation follows symlinks (same as the
        # prior exists()), so a dangling link reads as gone.
        # No in-system producer symlinks a fixture root.
        tmp = tempfile.mkdtemp(prefix="e2e-pin-")
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        run = os.path.join(tmp, "run")
        os.symlink(os.path.join(tmp, "target"), run)
        self.assertTrue(fixture_root_gone(run))

    def test_retain_decision_matrix(self):
        # S130: automatic removal of the ORIGINAL fixture is
        # conditional on PROVEN retirement — anything else
        # retains it for recovery.
        self.assertFalse(e2e_retirement_retains_tmp("retired"))
        self.assertTrue(e2e_retirement_retains_tmp("preserve"))

    def test_remove_helper_removes_when_not_retained(self):
        tmp = tempfile.mkdtemp(prefix="e2e-pin-")
        gone = os.path.join(tmp, "run")
        os.makedirs(gone)
        self.assertTrue(remove_tmp_unless_retained(tmp, False))
        self.assertFalse(os.path.exists(tmp))

    def test_remove_helper_retains_original_when_retained(self):
        # S130: retention keeps the ORIGINAL directory (same
        # inodes the manifest names), loudly, for manual
        # recovery — never a quiet rmtree past copies.
        import io
        from unittest import mock
        tmp = tempfile.mkdtemp(prefix="e2e-pin-")
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        run = os.path.join(tmp, "run")
        os.makedirs(os.path.join(run, "ext4"))
        manifest = os.path.join(tmp, "manifest.json")
        with open(manifest, "w") as handle:
            handle.write('{"run_root": "%s"}' % run)
        before = (os.stat(run), os.stat(manifest))
        captured = io.StringIO()
        with mock.patch("sys.stderr", captured):
            self.assertFalse(
                remove_tmp_unless_retained(tmp, True))
        self.assertIn(tmp, captured.getvalue())
        self.assertIn("RETAINED", captured.getvalue())
        after = (os.stat(run), os.stat(manifest))
        self.assertEqual(
            [(st.st_dev, st.st_ino) for st in after],
            [(st.st_dev, st.st_ino) for st in before])

    def test_preserve_records_original_identity(self):
        # S130: the preserved REASON names the ORIGINAL
        # run/manifest identities, so recovery can verify it
        # holds the same objects the manifest names (copies
        # have new inodes and prove nothing by themselves).
        import io
        from unittest import mock
        tmp = tempfile.mkdtemp(prefix="e2e-pin-")
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        run = os.path.join(tmp, "run")
        os.makedirs(run)
        manifest = os.path.join(tmp, "manifest.json")
        with open(manifest, "w") as handle:
            handle.write('{}')
        captured = io.StringIO()
        with mock.patch("sys.stderr", captured):
            dest = preserve_e2e_evidence(
                run, manifest, "cleanup rc=1 for pins")
        self.addCleanup(shutil.rmtree, dest, ignore_errors=True)
        with open(os.path.join(dest, "REASON")) as handle:
            reason = handle.read()
        run_st = os.stat(run)
        manifest_st = os.stat(manifest)
        self.assertIn(
            f"run_identity=dev:{run_st.st_dev} "
            f"ino:{run_st.st_ino}", reason)
        self.assertIn(
            f"manifest_identity=dev:{manifest_st.st_dev} "
            f"ino:{manifest_st.st_ino}", reason)

    def test_retain_plus_preserve_keeps_recoverable_original(self):
        # S130: the full failed-retirement path — the verdict
        # retains the ORIGINAL (same inodes, manifest still
        # names valid paths) while the copies land outside the
        # fixture root. Recoverability, not just copied bytes.
        import io
        import json as _json
        from unittest import mock
        tmp = tempfile.mkdtemp(prefix="e2e-pin-")
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        run = os.path.join(tmp, "run")
        os.makedirs(os.path.join(run, "ext4"))
        manifest = os.path.join(tmp, "manifest.json")
        with open(manifest, "w") as handle:
            handle.write(_json.dumps({"run_root": run}))
        with open(os.path.join(run, "ext4", "a.bin"),
                  "w") as handle:
            handle.write("payload")
        verdict = e2e_retirement_verdict(
            False, None, False, False)
        retain = e2e_retirement_retains_tmp(verdict)
        self.assertTrue(retain)
        captured = io.StringIO()
        with mock.patch("sys.stderr", captured):
            dest = preserve_e2e_evidence(
                run, manifest, "cleanup rc=1 for pins")
            removed = remove_tmp_unless_retained(tmp, retain)
        self.addCleanup(shutil.rmtree, dest, ignore_errors=True)
        self.assertFalse(removed)
        self.assertFalse(dest.startswith(tmp + os.sep))
        # The original is recoverable in place: same bytes,
        # and the manifest's recorded paths still resolve.
        with open(os.path.join(
                dest, "run", "ext4", "a.bin")) as handle:
            self.assertEqual(handle.read(), "payload")
        with open(manifest) as handle:
            doc = _json.load(handle)
        self.assertTrue(os.path.isdir(doc["run_root"]))
        with open(os.path.join(
                doc["run_root"], "ext4", "a.bin")) as handle:
            self.assertEqual(handle.read(), "payload")

    def test_false_cleanup_success_preserves_original(self):
        # R10-010: cleanup rc 0 with clean mount tables but a
        # STANDING root is false success — the verdict
        # preserves (never retires), the ORIGINAL tmpdir is
        # retained in place with manifest identities intact,
        # and the copies land outside the fixture root.
        import io
        import json as _json
        from unittest import mock
        tmp = tempfile.mkdtemp(prefix="e2e-pin-")
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        run = os.path.join(tmp, "run")
        os.makedirs(os.path.join(run, "ext4"))
        manifest = os.path.join(tmp, "manifest.json")
        with open(manifest, "w") as handle:
            handle.write(_json.dumps({"run_root": run}))
        with open(os.path.join(run, "ext4", "a.bin"),
                  "w") as handle:
            handle.write("payload")
        verdict = e2e_retirement_verdict(True, [], True, False)
        self.assertEqual(verdict, "preserve")
        retain = e2e_retirement_retains_tmp(verdict)
        self.assertTrue(retain)
        captured = io.StringIO()
        with mock.patch("sys.stderr", captured):
            dest = preserve_e2e_evidence(
                run, manifest,
                "cleanup rc=0 leftovers=[] host_clean=True "
                "root_gone=False for pins")
            removed = remove_tmp_unless_retained(tmp, retain)
        self.addCleanup(shutil.rmtree, dest, ignore_errors=True)
        self.assertFalse(removed)
        self.assertFalse(dest.startswith(tmp + os.sep))
        with open(manifest) as handle:
            doc = _json.load(handle)
        self.assertTrue(os.path.isdir(doc["run_root"]))
        with open(os.path.join(
                doc["run_root"], "ext4", "a.bin")) as handle:
            self.assertEqual(handle.read(), "payload")


class UnpinnedMovedUncertaintyTests(unittest.TestCase):
    # S136: the pre-pin overlay rename reports uncertainty with
    # NON-authoritative observations — the helper's embedded
    # mnt=/observed-at text is never parsed into custody, and
    # reconcile/cleanup keep ID-less pending custody that can
    # only report unprovable absence loudly. The live pre-pin
    # rename test wires this contract to a real kernel move;
    # these pins cover the decision chain without privilege.
    # The helper text mirrors the S108 production wording
    # exactly (provision._recover_unpinned_mount).
    HELPER_OUT = (
        "FAILED-UNCERTAIN: mount /tmp/s136/run/ov/merged pin "
        "failed (target not openable: [Errno 2] No such file "
        "or directory); unpinned moved candidate (mnt=41 "
        "observed at '/tmp/s136/escaped/merged') lacks "
        "held-upper binding; left in place; manual retirement "
        "required\n")

    def setUp(self):
        self.saved_persist = provision._PERSIST

    def tearDown(self):
        provision._PERSIST = self.saved_persist

    def test_uncertain_output_has_no_parseable_moved_report(self):
        out = self.HELPER_OUT
        self.assertIn("FAILED-UNCERTAIN", out)
        self.assertNotIn("FAILED-MOVED", out)
        self.assertIsNone(provision._parse_moved_report(out))

    def test_normalize_and_classify_uncertain_without_identity(self):
        failure = provision._normalize_mount_failure(
            "/tmp/s136/run/ov/merged", 1, self.HELPER_OUT, "")
        self.assertIn("effect uncertain", failure)
        self.assertEqual(
            provision._classify_mount_failure(failure),
            ("uncertain", None, None))

    def _reconciled_doc(self, run):
        target = os.path.join(run, "ov", "merged")
        canary = "pin-canary"
        doc = provision.fresh_manifest(run, False)
        st = os.stat(run)
        doc["run_root_identity"] = {"dev": st.st_dev,
                                    "ino": st.st_ino}
        provision.record_pending_acquisition(doc, {
            "kind": "mount", "key": target, "role": "ov",
            "target": target, "fstype": "overlay",
            "source": "overlay", "expect_super": [],
            "canary": canary})
        failure = provision._normalize_mount_failure(
            target, 1, self.HELPER_OUT, "")
        adopted = provision.reconcile_mount_effect(
            doc, run, "ov", target,
            {"fstype": "overlay", "source": "overlay",
             "expect_super": []},
            canary=(provision.MOUNT_CANARY_NAME, canary),
            failure=failure)
        return (doc, target, adopted)

    def test_reconcile_keeps_id_less_pending(self):
        tmp = tempfile.mkdtemp(prefix="s136-pin-")
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        run = os.path.join(tmp, "run")
        os.makedirs(run)
        provision._PERSIST = None
        doc, _, adopted = self._reconciled_doc(run)
        self.assertIsNone(adopted)
        pendings = doc["pending_acquisitions"]
        self.assertEqual(len(pendings), 1)
        # No recovery identity: the unverified observation
        # text never becomes custody.
        self.assertNotIn("mnt_id", pendings[0])
        self.assertNotIn("observed_target", pendings[0])
        self.assertIn("uncertain",
                      pendings[0].get("detail", ""))

    def test_cleanup_reports_unprovable_absence_and_retains(self):
        tmp = tempfile.mkdtemp(prefix="s136-pin-")
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        run = os.path.join(tmp, "run")
        os.makedirs(run)
        provision._PERSIST = None
        doc, target, _ = self._reconciled_doc(run)
        failures = provision.cleanup_pending_acquisitions(
            doc, run)
        self.assertEqual(len(failures), 1)
        self.assertIn("cannot prove absence", failures[0])
        self.assertIn("custody kept pending", failures[0])
        # Cleanup never learns the escaped location: the
        # observation stays non-authoritative end to end.
        self.assertNotIn("escaped", failures[0])
        self.assertNotIn("mnt=41", failures[0])
        self.assertEqual(
            len(doc["pending_acquisitions"]), 1)


class RedirectedToolTests(unittest.TestCase):
    # S137: chosen entry subprocesses consult PRIVATE keeper
    # paths (stale or absent) instead of the healthy shared
    # keeper — an erroneous ensure inside unprivileged
    # creation/inspection can no longer silently reuse it. The
    # live no-keeper negative wires this into real entries
    # against a killed private keeper; these pins cover the
    # redirection mechanism plus real unprivileged entries
    # through it (no sudo, no keeper, no mounts).
    def test_probe_reports_private_paths(self):
        tmp = tempfile.mkdtemp(prefix="s137-pin-")
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        tool = write_redirected_tool(tmp)
        pidfile = os.path.join(tmp, "private.pid")
        candir = os.path.join(tmp, "private-canary")
        env = private_keeper_subprocess_env(pidfile, candir)
        probe = subprocess.run(
            [sys.executable, tool, "--probe-keeper-paths"],
            capture_output=True, text=True, timeout=60,
            env=env)
        self.assertEqual(probe.returncode, 0,
                         probe.stdout + probe.stderr)
        self.assertEqual(json.loads(probe.stdout),
                         [pidfile, candir])

    def test_probe_without_env_reports_shared_paths(self):
        tmp = tempfile.mkdtemp(prefix="s137-pin-")
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        tool = write_redirected_tool(tmp)
        env = dict(os.environ)
        env.pop(PRIVATE_KEEPER_PIDFILE_ENV, None)
        env.pop(PRIVATE_KEEPER_CANDIR_ENV, None)
        probe = subprocess.run(
            [sys.executable, tool, "--probe-keeper-paths"],
            capture_output=True, text=True, timeout=60,
            env=env)
        self.assertEqual(probe.returncode, 0,
                         probe.stdout + probe.stderr)
        self.assertEqual(json.loads(probe.stdout),
                         list(provision._keeper_paths()))

    def test_probe_ensure_refuses_corrupt_private_record(self):
        # Bad control: the stale state is really established in
        # the subprocess — a corrupt private record refuses
        # there instead of silently using the shared keeper
        # (live: a broken redirection would ENSURE via the
        # healthy shared keeper and fail this; bare: passes
        # vacuously since no keeper exists either way).
        tmp = tempfile.mkdtemp(prefix="s137-pin-")
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        tool = write_redirected_tool(tmp)
        pidfile = os.path.join(tmp, "private.pid")
        candir = os.path.join(tmp, "private-canary")
        with open(pidfile, "wb") as handle:
            handle.write(b"not a keeper record\n")
        env = private_keeper_subprocess_env(pidfile, candir)
        probe = subprocess.run(
            [sys.executable, tool, "--probe-ensure"],
            capture_output=True, text=True, timeout=60,
            env=env)
        self.assertEqual(probe.returncode, 0,
                         probe.stdout + probe.stderr)
        self.assertTrue(
            probe.stdout.startswith("REFUSED"),
            probe.stdout)
        self.assertIn("corrupt", probe.stdout)

    def test_unprivileged_entries_leave_stale_record_untouched(self):
        tmp = tempfile.mkdtemp(prefix="s137-pin-")
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        tool = write_redirected_tool(tmp)
        pidfile = os.path.join(tmp, "private.pid")
        candir = os.path.join(tmp, "private-canary")
        # A stale record (dead keeper): the entries must
        # neither respawn through it nor disturb it.
        with open(pidfile, "wb") as handle:
            handle.write(b"424242 77 dead-canary\n")
        with open(pidfile, "rb") as handle:
            stale = handle.read()
        global_pidfile, _ = provision._keeper_paths()
        try:
            with open(global_pidfile, "rb") as handle:
                global_before = handle.read()
        except OSError:
            global_before = None
        env = private_keeper_subprocess_env(pidfile, candir)
        run = os.path.join(tmp, "plain")
        manifest = os.path.join(tmp, "plain.json")

        def tool_run(*args, timeout=300):
            return subprocess.run(
                [sys.executable, tool, *args],
                capture_output=True, text=True,
                timeout=timeout, env=env)

        first = tool_run("create", "--manifest", manifest,
                         "--run-root", run)
        self.assertEqual(first.returncode, 0,
                         first.stdout + first.stderr)
        second = tool_run("inspect", "--manifest", manifest,
                          "--run-root", run)
        self.assertEqual(second.returncode, 0,
                         second.stdout + second.stderr)
        third = tool_run("create", "--manifest", manifest,
                         "--run-root", "/etc/shadow")
        self.assertEqual(third.returncode, 2,
                         third.stdout + third.stderr)
        with open(pidfile, "rb") as handle:
            self.assertEqual(handle.read(), stale)
        if global_before is not None:
            with open(global_pidfile, "rb") as handle:
                self.assertEqual(handle.read(), global_before)


class Ext4ArmVerdictTests(unittest.TestCase):
    # G1-I3: the E2E ext4-arm obligation, pinned without live
    # mounts (the live E2E test calls these helpers). The arm
    # is required on loop+mkfs-capable hosts; otherwise the
    # FS01 skip reason must name the missing capability.
    def test_verdict_matrix(self):
        self.assertEqual(
            ext4_arm_verdict(True, True, True), "verified")
        self.assertEqual(
            ext4_arm_verdict(True, False, False), "verified")
        self.assertEqual(
            ext4_arm_verdict(False, True, True), "required")
        self.assertEqual(
            ext4_arm_verdict(False, False, True), "skipped")
        self.assertEqual(
            ext4_arm_verdict(False, True, False), "skipped")
        self.assertEqual(
            ext4_arm_verdict(False, False, False), "skipped")

    def test_skip_reason_matrix(self):
        self.assertTrue(fs01_skip_reason_ok(
            "missing mkfs.ext4 tool"))
        self.assertTrue(fs01_skip_reason_ok(
            "losetup refused: rc=1 FAILED: loop-control not "
            "openable: [Errno 2] No such file or directory"))
        self.assertTrue(fs01_skip_reason_ok(
            "losetup refused: rc=1 FAILED: no free loop device: "
            "[Errno 19] No such device"))
        self.assertFalse(fs01_skip_reason_ok(""))
        self.assertFalse(fs01_skip_reason_ok(None))
        # Mount-stage failures imply loop worked: not a
        # capability skip, so they must not pass as one.
        self.assertFalse(fs01_skip_reason_ok(
            "ext4 mount not admitted (foreign replacement)"))
        self.assertFalse(fs01_skip_reason_ok(
            "some unrelated failure"))

    def test_skip_reason_rejects_formatter_and_utility_failures(self):
        # S113: production reports every formatter-helper
        # failure as "mkfs.ext4 refused" (before loop custody
        # is armed) — the old ("loop","losetup","mkfs")
        # substring classifier accepted it as a capability
        # skip. Bare "losetup refused" (utility failure, no
        # identified inner cause) is not missing capability
        # either: production attaches via native ioctls.
        self.assertFalse(fs01_skip_reason_ok(
            "mkfs.ext4 refused: rc=1 mkfs failed"))
        self.assertFalse(fs01_skip_reason_ok(
            "losetup refused: rc=127 /usr/sbin/losetup missing"))
        self.assertFalse(fs01_skip_reason_ok(
            "losetup refused: rc=1 FAILED: loop /dev/loop3 "
            "configure failed: [Errno 5] Input/output error"))
        # Uncertain custody is unresolved, never a clean skip;
        # integrity refusals are breakage, not unavailability.
        self.assertFalse(fs01_skip_reason_ok(
            "losetup outcome uncertain and backing identity "
            "matches several loops; acquisition kept pending"))
        self.assertFalse(fs01_skip_reason_ok(
            "losetup association not ours: kernel backing "
            "identity differs from the held image; acquisition "
            "kept pending"))

    def test_native_loop_probe_matrix(self):
        # S113: only a successful native probe (LOOP_VIABLE
        # marker from the loop-control ioctl) proves loop
        # viability. Anything else degrades to not-viable —
        # the E2E then takes the skip path, where the FS01
        # reason must still name a real missing capability.
        self.assertTrue(native_loop_probe_verdict(
            0, "LOOP_VIABLE 3\n"))
        self.assertFalse(native_loop_probe_verdict(
            1, ""))
        self.assertFalse(native_loop_probe_verdict(
            0, ""))
        self.assertFalse(native_loop_probe_verdict(
            0, None))
        self.assertFalse(native_loop_probe_verdict(
            1, "LOOP_VIABLE 3\n"))


if __name__ == "__main__":
    unittest.main()
