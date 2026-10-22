// SPDX-License-Identifier: Apache-2.0
//! Private trusted-fixture custody; reports corroborate an exact owned PID path.
//! This is not filesystem authority or protection against a hostile same-UID replacer.
use std::{
    io::{self, Write},
    os::unix::{ffi::OsStrExt, fs::MetadataExt},
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
};

pub fn report_root(root: &Path) -> io::Result<()> {
    let metadata = std::fs::symlink_metadata(root)?;
    let mut stdout = io::stdout().lock();
    writeln!(stdout, "OWNED_TEMP_ROOT={}", root.display())?;
    writeln!(
        stdout,
        "OWNED_TEMP_ROOT_ID={}:{}",
        metadata.dev(),
        metadata.ino()
    )?;
    stdout.flush()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn optional_hex(value: Option<&[u8]>) -> String {
    value.map_or_else(|| "null".into(), |bytes| format!("\"{}\"", hex(bytes)))
}

fn identity(value: Option<(u64, u64)>) -> String {
    value.map_or_else(|| "null".into(), |(dev, ino)| format!("[{dev},{ino}]"))
}

pub struct ChildOutcome {
    pub pid: Option<u32>,
    pub child_reaped: bool,
    pub output: Option<Output>,
    pub child_error: Option<String>,
    pub root_required: bool,
    pub expected_root: Option<PathBuf>,
    pub root_reports: usize,
    pub identity_reports: usize,
    pub reported_identity: Option<(u64, u64)>,
    pub observed_identity: Option<(u64, u64)>,
    pub report_error: Option<String>,
    pub cleanup_error: Option<String>,
    pub cleanup_status: &'static str,
    pub owned_temp_removed: bool,
}

impl ChildOutcome {
    pub fn child_success(&self) -> bool {
        self.child_reaped
            && self
                .output
                .as_ref()
                .is_some_and(|output| output.status.success())
    }

    pub fn custody_resolved(&self) -> bool {
        self.child_reaped && matches!(self.cleanup_status, "PASS" | "ABSENT" | "NOT_REQUIRED")
    }

    pub fn emit(&self, case: &str) {
        let exit = self.output.as_ref().and_then(|output| output.status.code());
        let stdout = self.output.as_ref().map(|output| output.stdout.as_slice());
        let stderr = self.output.as_ref().map(|output| output.stderr.as_slice());
        // Hex fields preserve paths/errors/output without a new JSON dependency.
        println!(
            concat!(
                "BP02_CHILD_CUSTODY={{\"schema_version\":1,\"case_hex\":\"{}\",",
                "\"child_pid\":{},\"child_reaped\":{},\"child_exit\":{},\"child_success\":{},",
                "\"root_required\":{},\"expected_temp_root_hex\":{},\"root_report_count\":{},",
                "\"identity_report_count\":{},\"reported_identity\":{},\"observed_identity\":{},",
                "\"report_error_hex\":{},\"cleanup_error_hex\":{},\"child_error_hex\":{},",
                "\"cleanup_status\":\"{}\",\"owned_temp_removed\":{},\"custody_unresolved\":{},",
                "\"child_stdout_hex\":{},\"child_stderr_hex\":{}}}"
            ),
            hex(case.as_bytes()),
            self.pid
                .map_or_else(|| "null".into(), |pid| pid.to_string()),
            self.child_reaped,
            exit.map_or_else(|| "null".into(), |code| code.to_string()),
            self.child_success(),
            self.root_required,
            optional_hex(
                self.expected_root
                    .as_ref()
                    .map(|root| root.as_os_str().as_bytes())
            ),
            self.root_reports,
            self.identity_reports,
            identity(self.reported_identity),
            identity(self.observed_identity),
            optional_hex(self.report_error.as_ref().map(|error| error.as_bytes())),
            optional_hex(self.cleanup_error.as_ref().map(|error| error.as_bytes())),
            optional_hex(self.child_error.as_ref().map(|error| error.as_bytes())),
            self.cleanup_status,
            self.owned_temp_removed,
            !self.custody_resolved(),
            optional_hex(stdout),
            optional_hex(stderr)
        );
    }

    fn cleanup(&mut self) {
        if !self.child_reaped {
            self.cleanup_status = if self.pid.is_some() {
                "UNRESOLVED"
            } else {
                "NOT_STARTED"
            };
            return;
        }
        let root = self.expected_root.as_ref().unwrap();
        let stdout = String::from_utf8_lossy(&self.output.as_ref().unwrap().stdout);
        let roots: Vec<_> = stdout
            .lines()
            .filter_map(|line| line.strip_prefix("OWNED_TEMP_ROOT="))
            .collect();
        let identities: Vec<_> = stdout
            .lines()
            .filter_map(|line| line.strip_prefix("OWNED_TEMP_ROOT_ID="))
            .collect();
        self.root_reports = roots.len();
        self.identity_reports = identities.len();
        if identities.len() == 1 {
            self.reported_identity = identities[0].split_once(':').and_then(|(dev, ino)| {
                if dev.is_empty()
                    || ino.is_empty()
                    || !dev.bytes().all(|byte| byte.is_ascii_digit())
                    || !ino.bytes().all(|byte| byte.is_ascii_digit())
                {
                    return None;
                }
                Some((dev.parse::<u64>().ok()?, ino.parse::<u64>().ok()?))
            });
        }
        let metadata = match std::fs::symlink_metadata(root) {
            Ok(metadata) => metadata,
            Err(error)
                if error.kind() == io::ErrorKind::NotFound
                    && roots.is_empty()
                    && identities.is_empty() =>
            {
                self.cleanup_status = if self.root_required {
                    "ABSENT"
                } else {
                    "NOT_REQUIRED"
                };
                return;
            }
            Err(error) => {
                self.cleanup_status = "UNRESOLVED";
                self.report_error = Some(format!("expected owned root unavailable: {error}"));
                return;
            }
        };
        self.observed_identity = Some((metadata.dev(), metadata.ino()));
        if !self.root_required
            || roots.len() != 1
            || identities.len() != 1
            || Path::new(roots[0]) != root
            || !metadata.file_type().is_dir()
            || self.reported_identity != self.observed_identity
        {
            self.cleanup_status = "UNRESOLVED";
            self.report_error = Some("owned root report/path/type/dev/inode mismatch".into());
            return;
        }
        // The exact expected PID path is the only deletion candidate. The
        // trusted child report corroborates it; it never selects another path.
        match std::fs::remove_dir_all(root) {
            Ok(()) => match std::fs::symlink_metadata(root) {
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    self.cleanup_status = "PASS";
                    self.owned_temp_removed = true;
                }
                result => {
                    self.cleanup_status = "UNRESOLVED";
                    self.cleanup_error = Some(format!("owned root absence unproved: {result:?}"));
                }
            },
            Err(error) => {
                self.cleanup_status = "UNRESOLVED";
                self.cleanup_error = Some(error.to_string());
            }
        }
    }
}

pub fn run(mut command: Command, root_required: bool, temp_dir: &Path) -> ChildOutcome {
    let mut outcome = ChildOutcome {
        pid: None,
        child_reaped: false,
        output: None,
        child_error: None,
        root_required,
        expected_root: None,
        root_reports: 0,
        identity_reports: 0,
        reported_identity: None,
        observed_identity: None,
        report_error: None,
        cleanup_error: None,
        cleanup_status: "NOT_STARTED",
        owned_temp_removed: false,
    };
    match command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(child) => {
            outcome.pid = Some(child.id());
            outcome.expected_root = Some(temp_dir.join(format!("scopebase-bp02-{}", child.id())));
            match child.wait_with_output() {
                Ok(output) => {
                    outcome.child_reaped = true;
                    outcome.output = Some(output);
                }
                Err(error) => outcome.child_error = Some(error.to_string()),
            }
        }
        Err(error) => outcome.child_error = Some(error.to_string()),
    }
    outcome.cleanup();
    outcome
}
