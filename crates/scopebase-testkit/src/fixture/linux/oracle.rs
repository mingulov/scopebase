// SPDX-License-Identifier: Apache-2.0
//! Ported donor oracle facets for the TT03 first increment.
//!
//! Grant: OWNER-2026-10-23 (user-owned donor slices to Apache-2.0).
//!
//! | Facet | Donor slice | Disposition |
//! |---|---|---|
//! | TT03-SF-06 `exited_unreaped` | P `src/process.rs:2343-2367` @ `2c2713e66292b0d2688508a25f79e813ae823d81` | ADAPT: finite EINTR budget, rustix waitid, no raw-PID reacquisition |
//! | TT03-SF-09 generation vectors | P `src/process.rs:1555-1617` @ `2c2713e6` | VECTORS_ONLY: literal Current/Reused/Exited + Interrupted/denied/missing counterexamples |
//! | TT03-SF-10 absence vectors | P `src/process.rs:1745-1760` @ `2c2713e6` | VECTORS_ONLY: NotFound differs from denied/malformed/live |
//! | TT03-SF-11 tricky comm | P `src/process.rs:1883-1917` @ `2c2713e6` | ADAPT: same literal name + live/zombie/reaped birth invariant, owned worker naming |
//!
//! SF-07 lifecycle order (P `src/process.rs:2381-2384,2388-2392,2396-2400,2404-2410`)
//! and SF-14 no-control (O `tests/target_lifecycle.rs:359-375` @ `4bcb24ce2ad23faf3db7c95bf05fb9e85ce4c59a`)
//! are preserved through the driver schedule and integration tests; see driver.rs.
use std::fmt;
use std::io;

/// Exact tricky comm from SF-11: nine bytes `a) Z 1 (b`.
pub const TRICKY_COMM: &str = "a) Z 1 (b";
/// Lowercase hex of [`TRICKY_COMM`]: `6129205a2031202862`.
pub const TRICKY_COMM_HEX: &str = "6129205a2031202862";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OracleError {
    detail: String,
}
impl OracleError {
    fn new(detail: impl Into<String>) -> Self {
        Self {
            detail: detail.into(),
        }
    }
    pub fn detail(&self) -> &str {
        &self.detail
    }
}
impl fmt::Display for OracleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "oracle: {}", self.detail)
    }
}
impl std::error::Error for OracleError {}

/// Original-owned-child WNOWAIT witness (SF-06, adapted).
///
/// `Some(si_code)` once the owned child has exited but is unreaped,
/// `None` while it still runs. EINTR retries are bounded by
/// `max_attempts`; there is no unbounded loop and no wait-any fallback.
/// Reaped or foreign PIDs surface the kernel errno (ECHILD after the
/// exact recorded reap).
pub fn exited_unreaped_owned(pid: u32, max_attempts: u32) -> io::Result<Option<i32>> {
    if max_attempts == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "max_attempts must be positive",
        ));
    }
    let raw = i32::try_from(pid)
        .ok()
        .filter(|n| *n > 0)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "pid out of range"))?;
    let target = rustix::process::Pid::from_raw(raw).ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "pid must be positive")
    })?;
    let options = rustix::process::WaitIdOptions::EXITED
        | rustix::process::WaitIdOptions::NOHANG
        | rustix::process::WaitIdOptions::NOWAIT;
    let mut attempts = 0u32;
    loop {
        attempts += 1;
        match rustix::process::waitid(rustix::process::WaitId::Pid(target), options) {
            Ok(None) => return Ok(None),
            Ok(Some(status)) => return Ok(Some(status.raw_code())),
            Err(rustix::io::Errno::INTR) if attempts < max_attempts => continue,
            Err(e) => return Err(e.into()),
        }
    }
}

/// Classified original-generation evidence (SF-09, vectors only).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GenerationState {
    Current,
    Reused,
    Exited,
}

/// Independent generation oracle over the SF-09 counterexample vectors.
///
/// `exited` is the original pidfd poll outcome when one was taken,
/// `retained` the birth captured at spawn, `read_current` the fresh
/// same-generation read. A live pidfd decides Current without reading;
/// an exited pidfd decides Exited even for a same-generation zombie;
/// otherwise equal birth is Current, changed birth Reused, NotFound
/// Exited, and every other failure (including missing retained birth)
/// stays an error, never exit proof.
pub fn generation_of(
    exited: Option<io::Result<bool>>,
    retained: Option<u64>,
    read_current: impl FnOnce() -> io::Result<u64>,
) -> Result<GenerationState, OracleError> {
    match exited {
        Some(Ok(false)) => return Ok(GenerationState::Current),
        Some(Ok(true)) => return Ok(GenerationState::Exited),
        Some(Err(e)) => {
            return Err(OracleError::new(format!(
                "pidfd poll kept its error: {}",
                e.kind().as_str()
            )))
        }
        None => {}
    }
    let Some(retained) = retained else {
        return Err(OracleError::new("missing retained start time is unknown, never exit"));
    };
    match read_current() {
        Ok(current) => Ok(if current == retained {
            GenerationState::Current
        } else {
            GenerationState::Reused
        }),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(GenerationState::Exited),
        Err(e) => Err(OracleError::new(format!(
            "current read kept its error: {}",
            e.kind().as_str()
        ))),
    }
}

trait KindStr {
    fn as_str(&self) -> &'static str;
}
impl KindStr for io::ErrorKind {
    fn as_str(&self) -> &'static str {
        match self {
            io::ErrorKind::NotFound => "not_found",
            io::ErrorKind::PermissionDenied => "permission_denied",
            io::ErrorKind::Interrupted => "interrupted",
            _ => "other",
        }
    }
}

/// Only a missing process proves exit (SF-10, vectors only).
///
/// `Ok` (live birth), EACCES refusal and malformed-stat errors are not
/// exit; only NotFound is.
pub fn gone_from_result(read: &io::Result<u64>) -> bool {
    matches!(read, Err(e) if e.kind() == io::ErrorKind::NotFound)
}

/// Final-delimiter stat parse: comm between the first `(` and the LAST
/// `)`, then state plus starttime from fixed post-comm positions
/// (SF-11 oracle shape). Returns `(comm, state, starttime_ticks)`.
pub fn parse_stat_comm_state_starttime(stat: &[u8]) -> Result<(Vec<u8>, u8, u64), OracleError> {
    let open = stat
        .iter()
        .position(|b| *b == b'(')
        .ok_or_else(|| OracleError::new("stat lacks comm open delimiter"))?;
    let close = stat
        .iter()
        .rposition(|b| *b == b')')
        .ok_or_else(|| OracleError::new("stat lacks comm close delimiter"))?;
    if close <= open {
        return Err(OracleError::new("stat comm delimiters cross"));
    }
    let comm = stat[open + 1..close].to_vec();
    let rest: Vec<&[u8]> = stat[close + 1..].split(|b| b.is_ascii_whitespace()).collect();
    let rest: Vec<&[u8]> = rest.into_iter().filter(|f| !f.is_empty()).collect();
    if rest.len() < 20 {
        return Err(OracleError::new("stat has too few post-comm fields"));
    }
    if rest[0].len() != 1 {
        return Err(OracleError::new("stat state is not one byte"));
    }
    let start = std::str::from_utf8(rest[19])
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .ok_or_else(|| OracleError::new("stat starttime is not decimal"))?;
    Ok((comm, rest[0][0], start))
}

/// True only for actual zombie state, never for a live fake-Z comm.
pub fn stat_is_zombie(stat: &[u8]) -> Result<bool, OracleError> {
    Ok(parse_stat_comm_state_starttime(stat)?.1 == b'Z')
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    #[test]
    fn tricky_literal_bytes() {
        assert_eq!(TRICKY_COMM.as_bytes().len(), 9);
        let mut hex = String::new();
        for b in TRICKY_COMM.as_bytes() {
            hex.push_str(&format!("{b:02x}"));
        }
        assert_eq!(hex, TRICKY_COMM_HEX);
        assert_eq!(TRICKY_COMM_HEX, "6129205a2031202862");
    }

    #[test]
    fn generation_vectors_current_reused_exited() {
        let reads = Cell::new(0);
        assert_eq!(
            generation_of(Some(Ok(false)), None, || {
                reads.set(reads.get() + 1);
                Ok(10)
            })
            .unwrap(),
            GenerationState::Current
        );
        assert_eq!(reads.get(), 0, "a live pidfd needs no current read");
        assert_eq!(
            generation_of(None, Some(10), || Ok(10)).unwrap(),
            GenerationState::Current
        );
        assert_eq!(
            generation_of(None, Some(10), || Ok(11)).unwrap(),
            GenerationState::Reused
        );
        assert_eq!(
            generation_of(None, Some(10), || Err(io::Error::from(
                io::ErrorKind::NotFound
            )))
            .unwrap(),
            GenerationState::Exited
        );
        assert_eq!(
            generation_of(Some(Ok(true)), Some(10), || Ok(10)).unwrap(),
            GenerationState::Exited,
            "same-generation zombie with exited pidfd is exited"
        );
    }

    #[test]
    fn generation_vectors_keep_errors_and_missing() {
        assert_eq!(
            generation_of(
                Some(Err(io::Error::from(io::ErrorKind::Interrupted))),
                Some(10),
                || Ok(10)
            )
            .unwrap_err()
            .detail(),
            "pidfd poll kept its error: interrupted"
        );
        assert_eq!(
            generation_of(None, Some(10), || Err(io::Error::from(
                io::ErrorKind::PermissionDenied
            )))
            .unwrap_err()
            .detail(),
            "current read kept its error: permission_denied"
        );
        assert_eq!(
            generation_of(None, None, || Ok(10)).unwrap_err().detail(),
            "missing retained start time is unknown, never exit"
        );
    }

    #[test]
    fn absence_vectors() {
        assert!(gone_from_result(&Err(io::Error::from(io::ErrorKind::NotFound))));
        assert!(!gone_from_result(&Ok(12345)));
        assert!(!gone_from_result(&Err(io::Error::from_raw_os_error(13))));
        assert!(!gone_from_result(&Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "stat comm"
        ))));
        assert!(!gone_from_result(&Err(io::Error::from(
            io::ErrorKind::PermissionDenied
        ))));
    }

    #[test]
    fn stat_parser_vectors() {
        let live = b"4242 (a) Z 1 (b) R 1 1 1 0 0 0 0 0 0 0 0 0 0 0 20 0 1 0 987654 100 200";
        let (comm, state, start) = parse_stat_comm_state_starttime(live).unwrap();
        assert_eq!(comm, b"a) Z 1 (b");
        assert_eq!(state, b'R');
        assert_eq!(start, 987654);
        assert!(!stat_is_zombie(live).unwrap());
        let zombie =
            b"4242 (a) Z 1 (b) Z 1 1 1 0 0 0 0 0 0 0 0 0 0 0 20 0 1 0 987654 100 200";
        assert!(stat_is_zombie(zombie).unwrap());
        assert_eq!(
            parse_stat_comm_state_starttime(zombie).unwrap().2,
            987654
        );
        assert!(parse_stat_comm_state_starttime(b"12 (oops R 1 2").is_err());
        assert!(parse_stat_comm_state_starttime(b"12 (ok) R 1").is_err());
        assert!(parse_stat_comm_state_starttime(
            b"12 (ok) R 1 1 1 0 0 0 0 0 0 0 0 0 0 0 20 0 1 0 nope 1 2"
        )
        .is_err());
        let nested = b"7 ((x)) S 1 1 1 0 0 0 0 0 0 0 0 0 0 0 20 0 1 0 42 1 2";
        assert_eq!(parse_stat_comm_state_starttime(nested).unwrap().0, b"(x)");
    }

    #[test]
    fn wnowait_rejects_bad_inputs() {
        assert_eq!(
            exited_unreaped_owned(0, 4).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        assert_eq!(
            exited_unreaped_owned(1, 0).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        assert_eq!(
            exited_unreaped_owned(u32::MAX, 4).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
    }
}
