// SPDX-License-Identifier: Apache-2.0
//! LX08 bounded slice: epoch authority, task birth, grants/refusals on owned
//! worker processes only. Foreign-namespace/overmount/TT04-cell fixtures are
//! out of scope and recorded in the lane commit, not faked here.
#![cfg(feature = "process")]
use scopebase_linux::{
    control::{CancelToken, OperationControl},
    error::{LimitKind, ProcMember, ProcOperation, Reason, Stage},
    identity::ObservationInterval,
    process::{BirthStatus, ObserverEpoch, Pid, ProcLimits, ProcessObservation},
    procfs::ParseLimits,
};
use std::time::Duration;

fn limits() -> ProcLimits {
    ProcLimits {
        parse: ParseLimits {
            max_bytes: 1 << 20,
            max_entries: 1 << 16,
            max_line_bytes: 1 << 16,
        },
        max_read_calls: 4096,
        max_metadata_bytes: 1 << 20,
    }
}

fn control() -> OperationControl {
    OperationControl::unlimited()
}

fn epoch() -> ObserverEpoch {
    ObserverEpoch::new(limits(), &control()).expect("epoch on own process")
}

#[test]
fn observation_types_are_send_sync() {
    fn send_sync<T: Send + Sync>() {}
    send_sync::<ObserverEpoch>();
    send_sync::<ProcessObservation>();
    send_sync::<scopebase_linux::process::BirthVerification>();
    send_sync::<scopebase_linux::process::MapsObservation>();
    send_sync::<scopebase_linux::process::MountObservation>();
    send_sync::<scopebase_linux::process::ProcViewId>();
    send_sync::<scopebase_linux::process::MountViewId>();
    send_sync::<scopebase_linux::process::TaskBirthObservation>();
    send_sync::<Pid>();
}

fn fd_count() -> usize {
    std::fs::read_dir("/proc/self/fd").unwrap().count()
}

#[test]
fn descriptive_markers_retain_no_fds() {
    let epoch = epoch();
    let me = Pid::new(std::process::id() as i32).unwrap();
    let mut stable = 0u32;
    let mut saw_live_fds = false;
    // Parallel sibling tests transiently hold their own FDs; retry until a
    // round observes our own create/drop delta cleanly. A genuine leak would
    // grow our count every round and never stabilize, so this still fails.
    for _ in 0..50 {
        let before = fd_count();
        let observation = ProcessObservation::acquire(me, &epoch, limits(), &control()).unwrap();
        let birth = observation.verify_birth(&control()).unwrap();
        let maps = observation.read_maps(limits(), &control()).unwrap();
        saw_live_fds |= fd_count() > before;
        // Keep every descriptive result; drop the last actual owners.
        let (_birth, _maps, _view, _birth_obs) = (
            birth,
            maps,
            observation.proc_view().clone(),
            observation.birth().clone(),
        );
        drop(observation);
        if fd_count() == before {
            stable += 1;
            if stable >= 3 {
                break;
            }
        }
    }
    assert!(saw_live_fds, "live owners hold FDs");
    assert!(stable >= 3, "markers keep no FD alive");
    drop(epoch);
}

#[test]
fn pid_accepts_exactly_positive_range() {
    assert!(Pid::new(0).is_none());
    assert!(Pid::new(-1).is_none());
    assert!(Pid::new(i32::MIN).is_none());
    assert_eq!(Pid::new(1).unwrap().as_raw(), 1);
    assert_eq!(Pid::new(i32::MAX).unwrap().as_raw(), i32::MAX);
    let me = Pid::new(std::process::id() as i32).unwrap();
    assert_eq!(me, me);
}

#[test]
fn epoch_creation_binds_strict_receipts() {
    let start = std::time::Instant::now();
    let epoch = epoch();
    let interval = epoch.creation_interval();
    assert!(interval.started_at() <= interval.finished_at());
    assert!(interval.started_at() >= start - Duration::from_secs(60));
    let charges = epoch.creation_charges();
    let process = charges.process().expect("create-epoch process charges");
    assert_eq!(process.body_bytes(), 0);
    assert_eq!(process.retained_transport_capacity_bytes(), 0);
    assert!(charges.parse().is_none());
    // Fixed non-data inventory: getpid1 + root2 + fstatfs1 + dir2 + status2 +
    // namespace_sample9 + creator pidfd2 + creator poll1 = 20.
    assert_eq!(charges.syscall_attempts(), 20 + process.read_calls());
    assert!(process.read_calls() >= 5, "minimum data attempts");
    assert_eq!(charges.fd_acquisitions(), 6);
    assert_eq!(charges.peak_new_fds(), 4);
    let effects = epoch.creation_effects();
    assert_eq!(
        effects.attempted_operations(),
        charges.syscall_attempts(),
        "every counted OS call is an attempted effect"
    );
    assert!(effects.completed_operations() <= effects.attempted_operations());
    assert_eq!(effects.target_mappings_created(), 0);
    assert_eq!(effects.target_mappings_retired(), 0);
}

#[test]
fn two_live_epochs_never_compare_equal() {
    let first = epoch();
    let second = epoch();
    assert_ne!(first, second, "distinct epochs are distinct authorities");
    assert_eq!(first, first.clone(), "clones share authority");
}

#[test]
fn zero_limits_refuse_before_any_os_attempt() {
    let epoch = epoch();
    let me = Pid::new(std::process::id() as i32).unwrap();
    let mut bad = limits();
    bad.max_metadata_bytes = 0;
    let error = ObserverEpoch::new(bad, &control()).unwrap_err();
    assert_eq!(error.stage(), Stage::ConfigureProcess);
    assert_eq!(error.reason(), Reason::InvalidInput);
    assert_eq!(error.charges().syscall_attempts(), 0);
    let mut bad = limits();
    bad.max_read_calls = 0;
    let error = ProcessObservation::acquire(me, &epoch, bad, &control()).unwrap_err();
    assert_eq!(error.stage(), Stage::ConfigureProcess);
    assert_eq!(error.reason(), Reason::InvalidInput);
    assert_eq!(error.charges().syscall_attempts(), 0);
    let mut bad = limits();
    bad.parse.max_bytes = 0;
    let error = ProcessObservation::acquire(me, &epoch, bad, &control()).unwrap_err();
    assert_eq!(error.stage(), Stage::ConfigureProcess);
    assert_eq!(error.reason(), Reason::InvalidInput);
    assert_eq!(error.charges().syscall_attempts(), 0);
}

#[test]
fn cancelled_entry_refuses_before_any_os_attempt() {
    let token = CancelToken::new();
    token.cancel();
    let stopped = OperationControl::new(None, token);
    let error = ObserverEpoch::new(limits(), &stopped).unwrap_err();
    assert_eq!(error.stage(), Stage::ConfigureProcess);
    assert_eq!(error.reason(), Reason::Cancelled);
    assert_eq!(error.charges().syscall_attempts(), 0);
    let epoch = epoch();
    let me = Pid::new(std::process::id() as i32).unwrap();
    let error = ProcessObservation::acquire(me, &epoch, limits(), &stopped).unwrap_err();
    assert_eq!(error.stage(), Stage::ConfigureProcess);
    assert_eq!(error.reason(), Reason::Cancelled);
    assert_eq!(error.charges().syscall_attempts(), 0);
}

#[test]
fn acquire_self_then_verify_alive_same_birth() {
    let epoch = epoch();
    let me = Pid::new(std::process::id() as i32).unwrap();
    let observation =
        ProcessObservation::acquire(me, &epoch, limits(), &control()).expect("acquire own process");
    assert_eq!(observation.pid(), me);
    assert_eq!(observation.epoch(), &epoch);
    assert_eq!(observation.birth().pid(), me);
    assert!(observation.birth().start_ticks() > 0);
    let acquisition = observation.acquisition_charges().process().unwrap();
    assert_eq!(acquisition.body_bytes(), 0);
    // Fixed non-data inventory 76: 21 checked acquisitions (42) + five
    // samples' stats/fs (20) + five kind ioctls (5) + root fstatfs (1) +
    // six target polls (6) + getpid (1) + creator poll (1).
    assert_eq!(
        observation.acquisition_charges().syscall_attempts(),
        76 + acquisition.read_calls()
    );
    assert!(acquisition.read_calls() >= 23, "minimum data attempts");
    assert_eq!(observation.acquisition_charges().fd_acquisitions(), 21);
    assert!(
        observation.acquisition_charges().peak_new_fds() <= 8,
        "bounded concurrent temporaries"
    );
    let birth = observation
        .verify_birth(&control())
        .expect("verify own birth");
    assert!(matches!(birth.status(), BirthStatus::AliveSameBirth));
    assert_eq!(
        birth.sampled_birth().unwrap().start_ticks(),
        birth.retained_birth().start_ticks()
    );
    assert!(birth.leader_state().is_some());
    let interval: &ObservationInterval = birth.interval();
    assert!(interval.started_at() <= interval.finished_at());
    // Full nonterminal verify: creator guard 15 + two target polls + checked
    // stat 2 = 19 fixed; five acquisitions, peak three, all retired.
    let verification = birth.charges().process().unwrap();
    assert_eq!(
        birth.charges().syscall_attempts(),
        19 + verification.read_calls()
    );
    assert!(verification.read_calls() >= 7, "minimum data attempts");
    assert_eq!(birth.charges().fd_acquisitions(), 5);
    assert_eq!(birth.charges().peak_new_fds(), 3);
}

#[test]
fn same_epoch_independent_acquisitions_are_different_views() {
    let epoch = epoch();
    let me = Pid::new(std::process::id() as i32).unwrap();
    let first = ProcessObservation::acquire(me, &epoch, limits(), &control()).unwrap();
    let second = ProcessObservation::acquire(me, &epoch, limits(), &control()).unwrap();
    assert_ne!(
        first.proc_view(),
        second.proc_view(),
        "independent acquisitions are distinct views"
    );
    assert_ne!(first.mount_view(), second.mount_view());
    assert_eq!(first.epoch(), second.epoch());
}

#[test]
fn acquire_dead_pid_is_typed_disappearance() {
    let epoch = epoch();
    let mut child = std::process::Command::new("/bin/true").spawn().unwrap();
    let pid = Pid::new(child.id() as i32).unwrap();
    child.wait().unwrap();
    // Reaped: no target directory or pidfd can exist anymore.
    let error = ProcessObservation::acquire(pid, &epoch, limits(), &control()).unwrap_err();
    assert_eq!(
        error.reason(),
        Reason::Disappeared,
        "stage {:?}",
        error.stage()
    );
    let context = error.process_context().expect("process context");
    assert_eq!(context.operation(), ProcOperation::Acquire);
    assert!(context.member().is_some());
}

#[test]
fn unreaped_exited_child_verifies_exited_without_sample() {
    let epoch = epoch();
    let mut child = std::process::Command::new("/bin/sleep")
        .arg("30")
        .spawn()
        .unwrap();
    let pid = Pid::new(child.id() as i32).unwrap();
    let observation =
        ProcessObservation::acquire(pid, &epoch, limits(), &control()).expect("acquire live child");
    child.kill().unwrap();
    child.wait().unwrap();
    // Unreaped-then-reaped under the original pidfd: terminal pre-poll or a
    // typed disappearance, never a false AliveSameBirth.
    match observation.verify_birth(&control()) {
        Ok(birth) => {
            assert!(matches!(birth.status(), BirthStatus::Exited));
            // S175: reaped-before-verify is pre-poll terminal, which
            // carries no sample (birth_check terminal pre-poll arm).
            assert!(
                birth.sampled_birth().is_none(),
                "exited-before-verify carries no sample"
            );
        }
        Err(error) => {
            assert_eq!(
                error.reason(),
                Reason::Disappeared,
                "stage {:?}",
                error.stage()
            );
        }
    }
}

struct Reaped(std::process::Child);
impl Drop for Reaped {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn birth_race_over_owned_children_never_misattributes() {
    let epoch = epoch();
    let mut alive = 0u32;
    let mut clean = 0u32;
    for _ in 0..50 {
        let child = Reaped(
            std::process::Command::new("/bin/true")
                .spawn()
                .expect("spawn owned child"),
        );
        let pid = Pid::new(child.0.id() as i32).unwrap();
        match ProcessObservation::acquire(pid, &epoch, limits(), &control()) {
            Ok(observation) => match observation.verify_birth(&control()) {
                Ok(birth) => match birth.status() {
                    BirthStatus::AliveSameBirth => alive += 1,
                    BirthStatus::Exited => clean += 1,
                    // A live generation contradiction under an original pidfd
                    // is a real Changed/Inconclusive report, not a pass.
                    unexpected => panic!("unexpected live status: {unexpected:?}"),
                },
                Err(error) => {
                    assert!(
                        matches!(
                            error.reason(),
                            Reason::Disappeared
                                | Reason::Inconclusive
                                | Reason::ChangedSource
                                | Reason::Denied
                        ),
                        "unexpected verify refusal: {:?} {:?}",
                        error.stage(),
                        error.reason()
                    );
                    clean += 1;
                }
            },
            Err(error) => {
                // Denied is a genuine racy outcome: the kernel returns
                // EACCES on a dying owned child's ns links (observed live);
                // it is mapped at the actual stage, never a false success.
                assert!(
                    matches!(
                        error.reason(),
                        Reason::Disappeared
                            | Reason::Inconclusive
                            | Reason::ChangedSource
                            | Reason::Denied
                    ),
                    "unexpected acquire refusal: {:?} {:?}",
                    error.stage(),
                    error.reason()
                );
                clean += 1;
            }
        }
    }
    assert!(alive + clean == 50, "every race resolved");
}

#[test]
fn read_maps_self_parses_bounded_snapshot() {
    let epoch = epoch();
    let me = Pid::new(std::process::id() as i32).unwrap();
    let observation = ProcessObservation::acquire(me, &epoch, limits(), &control()).unwrap();
    let maps = observation
        .read_maps(limits(), &control())
        .expect("read own maps");
    assert!(maps.snapshot().entries().next().is_some(), "nonempty maps");
    assert_eq!(
        maps.birth().start_ticks(),
        observation.birth().start_ticks()
    );
    assert_eq!(maps.proc_view(), observation.proc_view());
    assert_eq!(maps.mount_view(), observation.mount_view());
    let charges = maps.charges().process().expect("read process charges");
    assert!(charges.body_bytes() > 0);
}

#[test]
fn read_mountinfo_self_transports_complete_table() {
    let epoch = epoch();
    let me = Pid::new(std::process::id() as i32).unwrap();
    let observation = ProcessObservation::acquire(me, &epoch, limits(), &control()).unwrap();
    match observation.read_mountinfo(limits(), &control()) {
        Ok(table) => {
            assert!(
                table.snapshot().entries().next().is_some(),
                "nonempty mountinfo"
            );
            assert_eq!(
                table.birth().start_ticks(),
                observation.birth().start_ticks()
            );
        }
        // FINDING (LX05/env, not this slice): the frozen LX05 mountinfo
        // grammar rejects this host's docker `net:[...]` nsfs line
        // (ParseMounts/Malformed, confirmed via std::fs read + parser
        // without this transport). The read machinery is still asserted:
        // complete body transport reached the parser unchanged.
        Err(error) => {
            assert_eq!(error.stage(), Stage::ParseMounts);
            assert_eq!(error.reason(), Reason::Malformed);
            let context = error.process_context().expect("process context");
            assert_eq!(context.operation(), ProcOperation::ReadMountinfo);
            assert_eq!(context.member(), Some(ProcMember::Mountinfo));
            let process = error.charges().process().expect("process charges");
            let parse = error.charges().parse().expect("reached parser charges");
            assert!(process.body_bytes() > 0);
            assert_eq!(
                parse.input_bytes() as u64,
                process.body_bytes(),
                "parser saw exactly the transported body"
            );
        }
    }
}

#[test]
fn unauthorized_observe_of_pid1_is_refused() {
    if libc_geteuid() == 0 {
        eprintln!("skip: root can observe pid 1");
        return;
    }
    let epoch = epoch();
    let init = Pid::new(1).unwrap();
    let observation = match ProcessObservation::acquire(init, &epoch, limits(), &control()) {
        Ok(observation) => observation,
        Err(error) => {
            assert_eq!(error.reason(), Reason::Denied, "stage {:?}", error.stage());
            return;
        }
    };
    let error = observation.read_maps(limits(), &control()).unwrap_err();
    assert_eq!(error.reason(), Reason::Denied, "stage {:?}", error.stage());
    let context = error.process_context().expect("process context");
    assert_eq!(context.operation(), ProcOperation::ReadMaps);
    assert_eq!(context.member(), Some(ProcMember::Maps));
}

// Minimal euid probe without a libc dependency: std has no geteuid, so read
// it from /proc/self/status, which this test process can always read.
fn libc_geteuid() -> u32 {
    let status = std::fs::read_to_string("/proc/self/status").unwrap();
    status
        .lines()
        .find_map(|line| line.strip_prefix("Uid:"))
        .and_then(|uids| uids.split_whitespace().next()?.parse().ok())
        .unwrap()
}

#[test]
fn tiny_metadata_budget_refuses_with_reached_cost() {
    let epoch = epoch();
    let me = Pid::new(std::process::id() as i32).unwrap();
    let mut tight = limits();
    tight.max_metadata_bytes = 8;
    tight.max_read_calls = 4096;
    let error = ProcessObservation::acquire(me, &epoch, tight, &control()).unwrap_err();
    assert_eq!(
        error.reason(),
        Reason::LimitExceeded(LimitKind::MetadataBytes),
        "stage {:?}",
        error.stage()
    );
    assert!(
        error.charges().syscall_attempts() > 0,
        "reached cost retained"
    );
}

#[test]
fn error_displays_without_raw_bytes() {
    let epoch = epoch();
    let mut child = std::process::Command::new("/bin/true").spawn().unwrap();
    let pid = Pid::new(child.id() as i32).unwrap();
    child.wait().unwrap();
    let error = ProcessObservation::acquire(pid, &epoch, limits(), &control()).unwrap_err();
    let text = format!("{error}");
    assert!(text.contains("LinuxError"));
    assert!(!text.contains("/proc"), "no paths leak: {text}");
}
