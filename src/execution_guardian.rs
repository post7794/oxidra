//! Process-external ownership of an MCP execution generation.
//!
//! The ordinary session writer lock belongs to the Oxidra host process.  A
//! separate guardian owns this second gate so host death cannot make a new MCP
//! generation runnable before the old native containment has exited.

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
#[cfg(target_os = "linux")]
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::path::{Path, PathBuf};
use std::process::ChildStdout;
use std::process::{Child, ChildStdin, Command, Stdio};
#[cfg(target_os = "linux")]
use std::sync::MutexGuard;
use std::sync::{Arc, Mutex};

use fs2::FileExt;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::error::{OxidraError, Result};
use crate::fs_security::{enforce_private_file, private_create_options};

const GUARDIAN_MODE: &str = "__internal-mcp-execution-guardian-v1";
const FRAME_MAGIC: [u8; 4] = *b"OXEG";
const FRAME_BYTES: usize = 16;
const FRAME_READY: u8 = 1;
#[cfg(target_os = "linux")]
const FRAME_REGISTER: u8 = 2;
#[cfg(target_os = "linux")]
const FRAME_REGISTERED: u8 = 3;
const FRAME_RELEASE: u8 = 4;
#[cfg(windows)]
const FRAME_SPAWN_PROCESS: u8 = 5;
#[cfg(windows)]
const FRAME_PROCESS_PREPARED: u8 = 6;
#[cfg(windows)]
const FRAME_PROCESS_PREPARE_FAILED: u8 = 7;
#[cfg(windows)]
const FRAME_RESUME_PROCESS: u8 = 8;
#[cfg(windows)]
const FRAME_PROCESS_RESUMED: u8 = 9;
#[cfg(windows)]
const FRAME_CANCEL_PROCESS: u8 = 10;
#[cfg(windows)]
const FRAME_PROCESS_CANCELLED: u8 = 11;
const GATE_STATE_MAGIC_V1: [u8; 8] = *b"OXEGST01";
const GATE_STATE_RECORD_BYTES_V1: usize = 64;
const GATE_STATE_CHECKSUM_OFFSET_V1: usize = 32;
const GATE_STATE_ACTIVE_V1: u8 = 1;
const GATE_STATE_CLEAN_V1: u8 = 2;
const MAX_GATE_STATE_BYTES_V1: u64 = 16 * 1024 * 1024;

/// A cloneable reference to the process-external execution gate.
///
/// The final in-process clone performs a normal guardian hand-off. If the host
/// is killed, no Rust destructor is required: the guardian observes its
/// anonymous control pipe close, terminates every registered containment, and
/// only then releases the gate.
pub(crate) struct ExecutionGuardianLeaseV1 {
    inner: Arc<ExecutionGuardianInnerV1>,
}

impl ExecutionGuardianLeaseV1 {
    pub(crate) fn start(execution_gate_path: &Path) -> Result<Self> {
        Self::start_inner(execution_gate_path, false)
    }

    #[cfg(windows)]
    pub(crate) fn start_ephemeral() -> Result<Self> {
        let path = std::env::temp_dir().join(format!(
            "oxidra-mcp-execution-{}-{}.lock",
            std::process::id(),
            uuid::Uuid::now_v7()
        ));
        Self::start_inner(&path, true)
    }

    fn start_inner(execution_gate_path: &Path, delete_gate_on_exit: bool) -> Result<Self> {
        let executable = guardian_executable()?;
        #[cfg(target_os = "linux")]
        let (registration_host, registration_guardian) = linux_registration_socket_pair_v1()?;
        let mut command = Command::new(&executable);
        command
            .arg(GUARDIAN_MODE)
            .arg("--execution-gate")
            .arg(execution_gate_path)
            .arg("--host-pid")
            .arg(std::process::id().to_string())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        if delete_gate_on_exit {
            command.arg("--delete-gate-on-exit");
        }
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::process::CommandExt;

            let registration_fd = registration_guardian.as_raw_fd();
            command
                .arg("--registration-fd")
                .arg(registration_fd.to_string());
            // The socketpair is created CLOEXEC in the multi-threaded host.
            // Clear that bit only in the already-forked guardian child so no
            // unrelated host spawn can inherit the registration endpoint.
            unsafe {
                command.pre_exec(move || linux_clear_cloexec_v1(registration_fd));
            }
        }
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;

            // The guardian must not share a supervisor Job failure domain
            // with the host. If the outer Job does not permit breakaway,
            // CreateProcess fails before the execution gate is acquired.
            const CREATE_BREAKAWAY_FROM_JOB: u32 = 0x0100_0000;
            #[cfg(debug_assertions)]
            let allow_same_job_for_test = {
                let explicitly_allowed =
                    std::env::var_os("OXIDRA_INTERNAL_GUARDIAN_ALLOW_SAME_JOB_V1").as_deref()
                        == Some(std::ffi::OsStr::new("1"));
                let integration_test_executable = delete_gate_on_exit
                    && std::env::current_exe()
                        .ok()
                        .and_then(|path| path.file_name().map(std::ffi::OsStr::to_owned))
                        .is_some_and(|name| !name.eq_ignore_ascii_case("oxidra.exe"));
                explicitly_allowed || integration_test_executable
            };
            #[cfg(not(debug_assertions))]
            let allow_same_job_for_test = false;
            if allow_same_job_for_test {
                // Debug integration-test executables commonly run inside a
                // non-breakaway Cargo/supervisor Job. Keep this bypass
                // explicit in the guardian environment; release builds can
                // never take it.
                command.env("OXIDRA_INTERNAL_GUARDIAN_ALLOW_SAME_JOB_V1", "1");
            } else {
                command.creation_flags(CREATE_BREAKAWAY_FROM_JOB);
            }
        }
        let mut child = command.spawn().map_err(|error| {
            OxidraError::Session(format!(
                "cannot start MCP execution guardian {}: {error}",
                executable.display()
            ))
        })?;
        #[cfg(target_os = "linux")]
        drop(registration_guardian);
        let stdin = child.stdin.take().ok_or_else(|| {
            OxidraError::Session("MCP execution guardian has no control input".to_owned())
        })?;
        let mut stdout = child.stdout.take().ok_or_else(|| {
            OxidraError::Session("MCP execution guardian has no control output".to_owned())
        })?;
        let ready = read_frame(&mut stdout).map_err(|error| {
            let _ = child.kill();
            let _ = child.wait();
            OxidraError::Session(format!(
                "MCP execution guardian did not establish its gate: {error}"
            ))
        })?;
        if ready.kind != FRAME_READY || ready.value == 0 {
            let _ = child.kill();
            let _ = child.wait();
            return Err(OxidraError::Session(
                "MCP execution guardian returned an invalid readiness proof".to_owned(),
            ));
        }
        #[cfg(debug_assertions)]
        publish_guardian_ready_for_fault_test_v1(ready.value);
        Ok(Self {
            inner: Arc::new(ExecutionGuardianInnerV1 {
                io: Mutex::new(Some(GuardianIoV1 {
                    child,
                    stdin,
                    stdout,
                    #[cfg(target_os = "linux")]
                    registration: registration_host,
                })),
            }),
        })
    }

    pub(crate) fn clone_v1(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn prepare_linux_registration(&self) -> Result<LinuxGuardianRegistrationV1<'_>> {
        let io = self.inner.io.lock().map_err(|_| {
            OxidraError::Session("MCP execution guardian control lock is poisoned".to_owned())
        })?;
        if io.is_none() {
            return Err(OxidraError::Session(
                "MCP execution guardian was already released".to_owned(),
            ));
        }
        Ok(LinuxGuardianRegistrationV1 { io })
    }

    #[cfg(windows)]
    pub(crate) fn spawn_windows_process(
        &self,
        command: &Path,
        args: &[String],
        cwd: Option<&Path>,
        inherited_env: &std::collections::BTreeMap<String, std::ffi::OsString>,
        explicit_env: &std::collections::BTreeMap<String, String>,
    ) -> Result<crate::process::WindowsContainedSpawnV1> {
        let payload = crate::process::windows_guardian_spawn_request_v1(
            command,
            args,
            cwd,
            inherited_env,
            explicit_env,
        )?;
        let mut io = self.inner.io.lock().map_err(|_| {
            OxidraError::Session("MCP execution guardian control lock is poisoned".to_owned())
        })?;
        let control = io.as_mut().ok_or_else(|| {
            OxidraError::Session("MCP execution guardian was already released".to_owned())
        })?;
        write_frame(
            &mut control.stdin,
            FrameV1::new(
                FRAME_SPAWN_PROCESS,
                u64::try_from(payload.len()).map_err(|_| {
                    OxidraError::Session(
                        "MCP execution guardian request length does not fit its protocol"
                            .to_owned(),
                    )
                })?,
            ),
        )?;
        control.stdin.write_all(&payload)?;
        control.stdin.flush()?;
        let acknowledgement = read_frame(&mut control.stdout)?;
        match acknowledgement.kind {
            FRAME_PROCESS_PREPARED if acknowledgement.value != 0 => {
                let spawn_id = acknowledgement.value;
                let mut response = [0u8; crate::process::WINDOWS_GUARDIAN_SPAWN_RESPONSE_BYTES_V1];
                if let Err(error) = control.stdout.read_exact(&mut response) {
                    cancel_windows_guardian_spawn_v1(control, spawn_id);
                    return Err(error.into());
                }
                let spawned =
                    match crate::process::windows_contained_spawn_from_guardian_response_v1(
                        &response,
                    ) {
                        Ok(spawned) => spawned,
                        Err(error) => {
                            cancel_windows_guardian_spawn_v1(control, spawn_id);
                            return Err(error.into());
                        }
                    };
                if let Err(error) = write_frame(
                    &mut control.stdin,
                    FrameV1::new(FRAME_RESUME_PROCESS, spawn_id),
                ) {
                    drop(spawned);
                    return Err(error.into());
                }
                let resumed = read_frame(&mut control.stdout);
                match resumed {
                    Ok(frame) if frame.kind == FRAME_PROCESS_RESUMED && frame.value == spawn_id => {
                        Ok(spawned)
                    }
                    Ok(frame) if frame.kind == FRAME_PROCESS_PREPARE_FAILED => {
                        drop(spawned);
                        Err(OxidraError::Session(format!(
                            "MCP execution guardian could not resume its atomic Windows child (os error {})",
                            frame.value
                        )))
                    }
                    Ok(_) => {
                        drop(spawned);
                        Err(OxidraError::Session(
                            "MCP execution guardian returned a mismatched Windows resume proof"
                                .to_owned(),
                        ))
                    }
                    Err(error) => {
                        drop(spawned);
                        Err(error.into())
                    }
                }
            }
            FRAME_PROCESS_PREPARE_FAILED => Err(OxidraError::Session(format!(
                "MCP execution guardian could not prepare an atomic Windows process (os error {})",
                acknowledgement.value
            ))),
            _ => Err(OxidraError::Session(
                "MCP execution guardian returned a mismatched Windows process preparation proof"
                    .to_owned(),
            )),
        }
    }
}

impl Clone for ExecutionGuardianLeaseV1 {
    fn clone(&self) -> Self {
        self.clone_v1()
    }
}

struct ExecutionGuardianInnerV1 {
    io: Mutex<Option<GuardianIoV1>>,
}

struct GuardianIoV1 {
    child: Child,
    stdin: ChildStdin,
    stdout: ChildStdout,
    #[cfg(target_os = "linux")]
    registration: OwnedFd,
}

impl Drop for ExecutionGuardianInnerV1 {
    fn drop(&mut self) {
        let slot = match self.io.get_mut() {
            Ok(slot) => slot,
            Err(poisoned) => poisoned.into_inner(),
        };
        let Some(mut io) = slot.take() else {
            return;
        };
        // The final lease is released only after all native transport reapers
        // have exited. Ask the guardian to verify/clean any registered process
        // before it gives up the cross-process execution gate.
        let _ = write_frame(&mut io.stdin, FrameV1::new(FRAME_RELEASE, 0));
        drop(io.stdin);
        let _ = io.child.wait();
    }
}

#[cfg(target_os = "linux")]
pub(crate) struct LinuxGuardianRegistrationV1<'a> {
    io: MutexGuard<'a, Option<GuardianIoV1>>,
}

#[cfg(target_os = "linux")]
impl LinuxGuardianRegistrationV1<'_> {
    pub(crate) fn configure(&self, command: &mut tokio::process::Command) -> Result<()> {
        use std::os::unix::process::CommandExt;

        let io = self.io.as_ref().ok_or_else(|| {
            OxidraError::Session("MCP execution guardian was already released".to_owned())
        })?;
        let write_fd = io.stdin.as_raw_fd();
        let read_fd = io.stdout.as_raw_fd();
        let registration_fd = io.registration.as_raw_fd();
        unsafe {
            command.as_std_mut().pre_exec(move || {
                let pid = nix::libc::getpid();
                if pid <= 0 {
                    return Err(linux_raw_error_v1(nix::libc::ESRCH));
                }
                let pidfd = nix::libc::syscall(nix::libc::SYS_pidfd_open, pid, 0);
                if pidfd == -1 {
                    return Err(linux_last_error_v1());
                }
                let register = FrameV1::new(FRAME_REGISTER, pid as u64).encode();
                let sent = linux_send_pidfd_v1(registration_fd, pidfd as RawFd, &register);
                let close_result = nix::libc::close(pidfd as RawFd);
                sent?;
                if close_result == -1 {
                    return Err(linux_last_error_v1());
                }
                write_all_fd_v1(write_fd, &register)?;
                let mut ack = [0u8; FRAME_BYTES];
                read_exact_fd_v1(read_fd, &mut ack)?;
                if !frame_matches_v1(&ack, FRAME_REGISTERED, pid as u64) {
                    return Err(linux_raw_error_v1(nix::libc::EPROTO));
                }
                Ok(())
            });
        }
        Ok(())
    }
}

#[cfg(windows)]
fn cancel_windows_guardian_spawn_v1(control: &mut GuardianIoV1, spawn_id: u64) {
    if write_frame(
        &mut control.stdin,
        FrameV1::new(FRAME_CANCEL_PROCESS, spawn_id),
    )
    .is_ok()
    {
        let _ = read_frame(&mut control.stdout)
            .map(|frame| frame.kind == FRAME_PROCESS_CANCELLED && frame.value == spawn_id);
    }
}

/// Fail closed before journal recovery if an older guardian still owns the
/// session's execution generation or died before proving containment empty.
pub(crate) fn ensure_execution_gate_quiescent_v1(path: &Path) -> Result<()> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    private_create_options(&mut options);
    let mut file = options.open(path)?;
    enforce_private_file(path)?;
    match file.try_lock_exclusive() {
        Ok(()) => {
            let state = read_execution_gate_state_v1(&mut file, path);
            FileExt::unlock(&file)?;
            state.map(|_| ())
        }
        Err(error) if execution_gate_is_contended_v1(&error) => Err(OxidraError::Session(
            "a prior MCP execution generation is still terminating".to_owned(),
        )),
        Err(error) => Err(error.into()),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ExecutionGateStateV1 {
    Clean,
    Active([u8; 16]),
}

fn read_execution_gate_state_v1(file: &mut File, path: &Path) -> Result<ExecutionGateStateV1> {
    let length = file.metadata()?.len();
    if length > MAX_GATE_STATE_BYTES_V1 {
        return Err(stale_execution_gate_error_v1(
            path,
            "state log is too large",
        ));
    }
    let record_bytes =
        u64::try_from(GATE_STATE_RECORD_BYTES_V1).expect("execution gate record size fits u64");
    if length % record_bytes != 0 {
        return Err(stale_execution_gate_error_v1(
            path,
            "state log ends with an incomplete record",
        ));
    }
    file.seek(SeekFrom::Start(0))?;
    let mut state = ExecutionGateStateV1::Clean;
    let mut record = [0u8; GATE_STATE_RECORD_BYTES_V1];
    for index in 0..(length / record_bytes) {
        file.read_exact(&mut record)?;
        let (kind, generation) = decode_execution_gate_record_v1(&record).ok_or_else(|| {
            stale_execution_gate_error_v1(path, &format!("record {index} is invalid"))
        })?;
        state = match (state, kind) {
            (ExecutionGateStateV1::Clean, GATE_STATE_ACTIVE_V1) => {
                ExecutionGateStateV1::Active(generation)
            }
            (ExecutionGateStateV1::Active(active), GATE_STATE_CLEAN_V1) if active == generation => {
                ExecutionGateStateV1::Clean
            }
            _ => {
                return Err(stale_execution_gate_error_v1(
                    path,
                    &format!("record {index} violates the generation state machine"),
                ));
            }
        };
    }
    file.seek(SeekFrom::End(0))?;
    match state {
        ExecutionGateStateV1::Clean => Ok(state),
        ExecutionGateStateV1::Active(_) => Err(stale_execution_gate_error_v1(
            path,
            "the previous guardian did not persist an exact containment-empty proof",
        )),
    }
}

fn append_execution_gate_state_v1(file: &mut File, state: u8, generation: [u8; 16]) -> Result<()> {
    let record = encode_execution_gate_record_v1(state, generation);
    file.seek(SeekFrom::End(0))?;
    file.write_all(&record)?;
    // ACTIVE must be durable before READY can authorize any child birth;
    // CLEAN must be durable before the kernel lock is released. A torn or
    // missing record is deliberately interpreted as permanent fail-closed
    // state by the next opener.
    file.sync_all()?;
    Ok(())
}

fn encode_execution_gate_record_v1(state: u8, generation: [u8; 16]) -> [u8; 64] {
    debug_assert!(matches!(state, GATE_STATE_ACTIVE_V1 | GATE_STATE_CLEAN_V1));
    let mut record = [0u8; GATE_STATE_RECORD_BYTES_V1];
    record[..8].copy_from_slice(&GATE_STATE_MAGIC_V1);
    record[8] = state;
    record[16..32].copy_from_slice(&generation);
    let checksum = Sha256::digest(&record[..GATE_STATE_CHECKSUM_OFFSET_V1]);
    record[GATE_STATE_CHECKSUM_OFFSET_V1..].copy_from_slice(&checksum);
    record
}

fn decode_execution_gate_record_v1(record: &[u8; 64]) -> Option<(u8, [u8; 16])> {
    if record[..8] != GATE_STATE_MAGIC_V1
        || !matches!(record[8], GATE_STATE_ACTIVE_V1 | GATE_STATE_CLEAN_V1)
        || record[9..16].iter().any(|byte| *byte != 0)
    {
        return None;
    }
    let checksum = Sha256::digest(&record[..GATE_STATE_CHECKSUM_OFFSET_V1]);
    if record[GATE_STATE_CHECKSUM_OFFSET_V1..] != checksum[..] {
        return None;
    }
    let mut generation = [0u8; 16];
    generation.copy_from_slice(&record[16..32]);
    if generation.iter().all(|byte| *byte == 0) {
        return None;
    }
    Some((record[8], generation))
}

fn stale_execution_gate_error_v1(path: &Path, reason: &str) -> OxidraError {
    OxidraError::Session(format!(
        "MCP execution generation gate {} is fail-closed and permanently quarantined: {reason}; in-place recovery is unsupported, use `oxidra session export <SESSION_ID> <ARCHIVE>.oxidra-session-export` for a read-only archive",
        path.display()
    ))
}

fn execution_gate_is_contended_v1(error: &io::Error) -> bool {
    if error.kind() == io::ErrorKind::WouldBlock {
        return true;
    }
    #[cfg(windows)]
    {
        // LockFileEx reports ERROR_LOCK_VIOLATION for a non-blocking conflict;
        // Rust currently classifies it as `Other`, not `WouldBlock`.
        matches!(error.raw_os_error(), Some(33))
    }
    #[cfg(not(windows))]
    false
}

#[derive(Clone, Copy)]
struct FrameV1 {
    kind: u8,
    value: u64,
}

impl FrameV1 {
    const fn new(kind: u8, value: u64) -> Self {
        Self { kind, value }
    }

    fn encode(self) -> [u8; FRAME_BYTES] {
        let mut bytes = [0u8; FRAME_BYTES];
        bytes[..4].copy_from_slice(&FRAME_MAGIC);
        bytes[4] = self.kind;
        bytes[8..16].copy_from_slice(&self.value.to_le_bytes());
        bytes
    }

    fn decode(bytes: [u8; FRAME_BYTES]) -> io::Result<Self> {
        if bytes[..4] != FRAME_MAGIC || bytes[5..8] != [0, 0, 0] {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid MCP execution guardian frame",
            ));
        }
        Ok(Self {
            kind: bytes[4],
            value: u64::from_le_bytes(bytes[8..16].try_into().expect("fixed frame value")),
        })
    }
}

fn write_frame(writer: &mut impl Write, frame: FrameV1) -> io::Result<()> {
    writer.write_all(&frame.encode())?;
    writer.flush()
}

fn read_frame(reader: &mut impl Read) -> io::Result<FrameV1> {
    let mut bytes = [0u8; FRAME_BYTES];
    reader.read_exact(&mut bytes)?;
    FrameV1::decode(bytes)
}

#[cfg(target_os = "linux")]
fn linux_raw_error_v1(errno: nix::libc::c_int) -> io::Error {
    io::Error::from_raw_os_error(errno)
}

#[cfg(target_os = "linux")]
fn linux_last_error_v1() -> io::Error {
    let errno = unsafe { *nix::libc::__errno_location() };
    linux_raw_error_v1(errno)
}

#[cfg(target_os = "linux")]
fn linux_registration_socket_pair_v1() -> io::Result<(OwnedFd, OwnedFd)> {
    let mut sockets = [-1; 2];
    let created = unsafe {
        nix::libc::socketpair(
            nix::libc::AF_UNIX,
            nix::libc::SOCK_SEQPACKET | nix::libc::SOCK_CLOEXEC,
            0,
            sockets.as_mut_ptr(),
        )
    };
    if created == -1 {
        return Err(io::Error::last_os_error());
    }
    let host = unsafe { OwnedFd::from_raw_fd(sockets[0]) };
    let guardian = unsafe { OwnedFd::from_raw_fd(sockets[1]) };
    Ok((host, guardian))
}

#[cfg(target_os = "linux")]
fn linux_clear_cloexec_v1(fd: RawFd) -> io::Result<()> {
    let flags = unsafe { nix::libc::fcntl(fd, nix::libc::F_GETFD) };
    if flags == -1 {
        return Err(linux_last_error_v1());
    }
    if unsafe { nix::libc::fcntl(fd, nix::libc::F_SETFD, flags & !nix::libc::FD_CLOEXEC) } == -1 {
        return Err(linux_last_error_v1());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn linux_send_pidfd_v1(socket: RawFd, pidfd: RawFd, frame: &[u8; FRAME_BYTES]) -> io::Result<()> {
    use std::mem::{size_of, zeroed};

    // One cmsghdr plus one c_int fits in this naturally aligned buffer on the
    // supported x86_64/aarch64 Linux targets. CMSG_SPACE remains the source of
    // truth for the actual length passed to the kernel.
    let mut control = [0usize; 4];
    let control_bytes = unsafe { nix::libc::CMSG_SPACE(size_of::<RawFd>() as u32) } as usize;
    if control_bytes > size_of::<[usize; 4]>() {
        return Err(linux_raw_error_v1(nix::libc::EOVERFLOW));
    }
    let mut iov = nix::libc::iovec {
        iov_base: frame.as_ptr().cast_mut().cast(),
        iov_len: frame.len(),
    };
    let mut message: nix::libc::msghdr = unsafe { zeroed() };
    message.msg_iov = &raw mut iov;
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    message.msg_controllen = control_bytes;
    let header = unsafe { nix::libc::CMSG_FIRSTHDR(&message) };
    if header.is_null() {
        return Err(linux_raw_error_v1(nix::libc::EOVERFLOW));
    }
    unsafe {
        (*header).cmsg_level = nix::libc::SOL_SOCKET;
        (*header).cmsg_type = nix::libc::SCM_RIGHTS;
        (*header).cmsg_len = nix::libc::CMSG_LEN(size_of::<RawFd>() as u32) as usize;
        nix::libc::CMSG_DATA(header).cast::<RawFd>().write(pidfd);
    }
    loop {
        let sent = unsafe { nix::libc::sendmsg(socket, &message, nix::libc::MSG_NOSIGNAL) };
        if sent == frame.len() as isize {
            return Ok(());
        }
        if sent == -1 {
            let error = linux_last_error_v1();
            if error.raw_os_error() == Some(nix::libc::EINTR) {
                continue;
            }
            return Err(error);
        }
        return Err(linux_raw_error_v1(nix::libc::EIO));
    }
}

#[cfg(target_os = "linux")]
fn frame_matches_v1(bytes: &[u8; FRAME_BYTES], kind: u8, value: u64) -> bool {
    bytes[..4] == FRAME_MAGIC
        && bytes[4] == kind
        && bytes[5..8] == [0, 0, 0]
        && bytes[8..16] == value.to_le_bytes()
}

#[cfg(target_os = "linux")]
fn write_all_fd_v1(fd: RawFd, mut bytes: &[u8]) -> io::Result<()> {
    while !bytes.is_empty() {
        let written = unsafe { nix::libc::write(fd, bytes.as_ptr().cast(), bytes.len()) };
        if written == -1 {
            let error = linux_last_error_v1();
            if error.raw_os_error() == Some(nix::libc::EINTR) {
                continue;
            }
            return Err(error);
        }
        if written == 0 {
            return Err(linux_raw_error_v1(nix::libc::EPIPE));
        }
        bytes = &bytes[written as usize..];
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn read_exact_fd_v1(fd: RawFd, mut bytes: &mut [u8]) -> io::Result<()> {
    while !bytes.is_empty() {
        let read = unsafe { nix::libc::read(fd, bytes.as_mut_ptr().cast(), bytes.len()) };
        if read == -1 {
            let error = linux_last_error_v1();
            if error.raw_os_error() == Some(nix::libc::EINTR) {
                continue;
            }
            return Err(error);
        }
        if read == 0 {
            return Err(linux_raw_error_v1(nix::libc::EPIPE));
        }
        let (_, remaining) = bytes.split_at_mut(read as usize);
        bytes = remaining;
    }
    Ok(())
}

fn guardian_executable() -> Result<PathBuf> {
    let current = std::env::current_exe()?;
    let executable_name = if cfg!(windows) {
        "oxidra.exe"
    } else {
        "oxidra"
    };
    let mut candidates = Vec::new();
    if current
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.eq_ignore_ascii_case(executable_name))
    {
        candidates.push(current.clone());
    }
    if let Some(parent) = current.parent() {
        candidates.push(parent.join(executable_name));
        if let Some(grandparent) = parent.parent() {
            candidates.push(grandparent.join(executable_name));
        }
    }
    candidates
        .into_iter()
        .find(|candidate| candidate.is_file())
        .ok_or_else(|| {
            OxidraError::Session(format!(
                "cannot locate the trusted MCP execution guardian beside {}",
                current.display()
            ))
        })
}

/// Hidden process entry point invoked by `src/main.rs` before CLI parsing.
#[doc(hidden)]
pub fn guardian_main_entry(arguments: impl IntoIterator<Item = std::ffi::OsString>) -> Result<()> {
    let mut arguments = arguments.into_iter();
    let mut execution_gate = None::<PathBuf>;
    let mut host_pid = None::<u32>;
    #[cfg(target_os = "linux")]
    let mut registration_fd = None::<RawFd>;
    let mut delete_gate_on_exit = false;
    while let Some(argument) = arguments.next() {
        match argument.to_str() {
            Some("--execution-gate") => {
                execution_gate = arguments.next().map(PathBuf::from);
            }
            Some("--host-pid") => {
                host_pid = arguments
                    .next()
                    .and_then(|value| value.to_str().and_then(|value| value.parse().ok()));
            }
            #[cfg(target_os = "linux")]
            Some("--registration-fd") => {
                registration_fd = arguments.next().and_then(|value| {
                    value
                        .to_str()
                        .and_then(|value| value.parse::<RawFd>().ok())
                        .filter(|value| *value >= 3)
                });
            }
            Some("--delete-gate-on-exit") => delete_gate_on_exit = true,
            _ => {
                return Err(OxidraError::Session(
                    "invalid MCP execution guardian bootstrap arguments".to_owned(),
                ));
            }
        }
    }
    let execution_gate = execution_gate.ok_or_else(|| {
        OxidraError::Session("MCP execution guardian has no execution gate path".to_owned())
    })?;
    let host_pid = host_pid.ok_or_else(|| {
        OxidraError::Session("MCP execution guardian has no host process identity".to_owned())
    })?;
    #[cfg(target_os = "linux")]
    let registration = registration_fd
        .map(|fd| unsafe { OwnedFd::from_raw_fd(fd) })
        .ok_or_else(|| {
            OxidraError::Session(
                "MCP execution guardian has no exact-pidfd registration socket".to_owned(),
            )
        })?;
    run_guardian(
        &execution_gate,
        host_pid,
        delete_gate_on_exit,
        #[cfg(target_os = "linux")]
        registration,
    )
}

fn run_guardian(
    execution_gate: &Path,
    host_pid: u32,
    delete_gate_on_exit: bool,
    #[cfg(target_os = "linux")] registration: OwnedFd,
) -> Result<()> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    private_create_options(&mut options);
    let mut gate = options.open(execution_gate)?;
    enforce_private_file(execution_gate)?;
    gate.try_lock_exclusive().map_err(|error| {
        OxidraError::Session(format!(
            "cannot acquire MCP execution generation gate {}: {error}",
            execution_gate.display()
        ))
    })?;
    read_execution_gate_state_v1(&mut gate, execution_gate)?;
    // A completed prior generation may be compacted before this generation
    // has authorized any code. If the guardian dies during this reset, an
    // empty file is safe: the new ACTIVE proof has not reached disk and READY
    // has not been published. Within one generation the log remains append
    // only, so a torn CLEAN can never erase the durable ACTIVE record.
    gate.set_len(0)?;
    gate.seek(SeekFrom::Start(0))?;
    gate.sync_all()?;
    #[cfg(windows)]
    let host_process = WindowsHostProcessV1::attach(host_pid)?;
    #[cfg(not(windows))]
    let _ = host_pid;

    let generation = *Uuid::now_v7().as_bytes();
    append_execution_gate_state_v1(&mut gate, GATE_STATE_ACTIVE_V1, generation)?;

    let mut output = io::stdout().lock();
    write_frame(
        &mut output,
        FrameV1::new(FRAME_READY, u64::from(std::process::id())),
    )?;
    drop(output);

    let mut input = io::stdin().lock();

    #[cfg(all(not(windows), not(target_os = "linux")))]
    let (normal_release, terminal_error) = match read_frame(&mut input) {
        Ok(frame) if frame.kind == FRAME_RELEASE && frame.value == 0 => (true, None),
        Ok(_) => (
            false,
            Some(OxidraError::Session(
                "MCP execution guardian received an invalid control frame".to_owned(),
            )),
        ),
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => (false, None),
        Err(error) => (false, Some(error.into())),
    };

    #[cfg(target_os = "linux")]
    let mut registered = Vec::new();
    #[cfg(target_os = "linux")]
    let mut normal_release = false;
    #[cfg(target_os = "linux")]
    let mut terminal_error = None::<OxidraError>;
    #[cfg(target_os = "linux")]
    loop {
        match read_frame(&mut input) {
            Ok(frame) if frame.kind == FRAME_RELEASE && frame.value == 0 => {
                normal_release = true;
                break;
            }
            #[cfg(target_os = "linux")]
            Ok(frame) if frame.kind == FRAME_REGISTER && frame.value != 0 => {
                let process_id = match u32::try_from(frame.value) {
                    Ok(process_id) if process_id != 0 => process_id,
                    _ => {
                        terminal_error = Some(OxidraError::Session(
                            "MCP execution guardian received an invalid Linux process identity"
                                .to_owned(),
                        ));
                        break;
                    }
                };
                linux_registration_fault_barrier_v1(process_id);
                let pidfd = match linux_receive_registered_pidfd_v1(&registration, process_id) {
                    Ok(pidfd) => pidfd,
                    Err(_) => {
                        // A missing or malformed SCM_RIGHTS transfer means the
                        // child cannot be tied to an exact kernel identity.
                        // Retain the gate forever rather than reopening the
                        // numeric PID or guessing at containment ownership.
                        loop {
                            std::thread::sleep(std::time::Duration::from_secs(60));
                        }
                    }
                };
                registered.push(pidfd);
                let mut output = io::stdout().lock();
                if let Err(error) =
                    write_frame(&mut output, FrameV1::new(FRAME_REGISTERED, frame.value))
                {
                    terminal_error = Some(error.into());
                    break;
                }
            }
            Ok(_) => {
                terminal_error = Some(OxidraError::Session(
                    "MCP execution guardian received an invalid control frame".to_owned(),
                ));
                break;
            }
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => break,
            Err(error) => {
                terminal_error = Some(error.into());
                break;
            }
        }
    }

    #[cfg(windows)]
    let mut registered = Vec::new();
    #[cfg(windows)]
    let mut normal_release = false;
    #[cfg(windows)]
    let mut terminal_error = None::<OxidraError>;
    #[cfg(windows)]
    let mut next_spawn_id = 1u64;
    #[cfg(windows)]
    loop {
        match read_frame(&mut input) {
            Ok(frame) if frame.kind == FRAME_RELEASE && frame.value == 0 => {
                normal_release = true;
                break;
            }
            Ok(frame)
                if frame.kind == FRAME_SPAWN_PROCESS
                    && frame.value != 0
                    && usize::try_from(frame.value).is_ok_and(|bytes| {
                        bytes <= crate::process::MAX_WINDOWS_GUARDIAN_SPAWN_REQUEST_BYTES_V1
                    }) =>
            {
                let mut payload = vec![0u8; frame.value as usize];
                if let Err(error) = input.read_exact(&mut payload) {
                    terminal_error = Some(error.into());
                    break;
                }
                let prepared = match host_process.spawn_process(&payload) {
                    Ok(prepared) => prepared,
                    Err(error) => {
                        let mut output = io::stdout().lock();
                        if let Err(write_error) = write_frame(
                            &mut output,
                            FrameV1::new(
                                FRAME_PROCESS_PREPARE_FAILED,
                                windows_error_code_v1(&error),
                            ),
                        ) {
                            terminal_error = Some(write_error.into());
                            break;
                        }
                        continue;
                    }
                };
                let spawn_id = next_spawn_id;
                next_spawn_id = match next_spawn_id.checked_add(1) {
                    Some(next) => next,
                    None => {
                        crate::process::windows_terminate_job_and_wait_empty_v1(&prepared.job);
                        terminal_error = Some(OxidraError::Session(
                            "MCP execution guardian exhausted Windows spawn identities".to_owned(),
                        ));
                        break;
                    }
                };
                let crate::process::WindowsGuardianPreparedSpawnV1 {
                    job,
                    primary_thread,
                    remote_handles,
                    response,
                } = prepared;
                registered.push(job);
                let mut output = io::stdout().lock();
                if let Err(error) =
                    write_frame(&mut output, FrameV1::new(FRAME_PROCESS_PREPARED, spawn_id))
                        .and_then(|()| output.write_all(&response))
                        .and_then(|()| output.flush())
                {
                    host_process.close_remote_handles(&remote_handles);
                    terminal_error = Some(error.into());
                    break;
                }
                drop(output);
                match read_frame(&mut input) {
                    Ok(frame) if frame.kind == FRAME_RESUME_PROCESS && frame.value == spawn_id => {
                        if let Err(error) =
                            crate::process::windows_resume_guardian_spawn_v1(&primary_thread)
                        {
                            crate::process::windows_terminate_job_and_wait_empty_v1(
                                registered.last().expect("registered Windows MCP Job"),
                            );
                            let mut output = io::stdout().lock();
                            if let Err(write_error) = write_frame(
                                &mut output,
                                FrameV1::new(
                                    FRAME_PROCESS_PREPARE_FAILED,
                                    windows_error_code_v1(&error),
                                ),
                            ) {
                                terminal_error = Some(write_error.into());
                                break;
                            }
                            continue;
                        }
                        let mut output = io::stdout().lock();
                        if let Err(error) =
                            write_frame(&mut output, FrameV1::new(FRAME_PROCESS_RESUMED, spawn_id))
                        {
                            terminal_error = Some(error.into());
                            break;
                        }
                    }
                    Ok(frame) if frame.kind == FRAME_CANCEL_PROCESS && frame.value == spawn_id => {
                        host_process.close_remote_handles(&remote_handles);
                        crate::process::windows_terminate_job_and_wait_empty_v1(
                            registered.last().expect("registered Windows MCP Job"),
                        );
                        let mut output = io::stdout().lock();
                        if let Err(error) = write_frame(
                            &mut output,
                            FrameV1::new(FRAME_PROCESS_CANCELLED, spawn_id),
                        ) {
                            terminal_error = Some(error.into());
                            break;
                        }
                    }
                    Ok(_) => {
                        terminal_error = Some(OxidraError::Session(
                            "MCP execution guardian received an invalid Windows spawn decision"
                                .to_owned(),
                        ));
                        break;
                    }
                    Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => break,
                    Err(error) => {
                        terminal_error = Some(error.into());
                        break;
                    }
                }
            }
            Ok(_) => {
                terminal_error = Some(OxidraError::Session(
                    "MCP execution guardian received an invalid control frame".to_owned(),
                ));
                break;
            }
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => break,
            Err(error) => {
                terminal_error = Some(error.into());
                break;
            }
        }
    }

    if !normal_release {
        guardian_fault_barrier_v1("host-death-observed", "allow-terminate");
    }
    #[cfg(target_os = "linux")]
    linux_terminate_and_wait_registered(&registered);
    #[cfg(windows)]
    windows_terminate_and_wait_registered(&registered);
    #[cfg(not(windows))]
    let _ = normal_release;

    if !normal_release {
        guardian_fault_barrier_v1("containment-empty", "allow-unlock");
    }

    append_execution_gate_state_v1(&mut gate, GATE_STATE_CLEAN_V1, generation)?;
    FileExt::unlock(&gate)?;
    drop(gate);
    if delete_gate_on_exit {
        let _ = std::fs::remove_file(execution_gate);
    }
    match terminal_error {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

#[cfg(debug_assertions)]
fn guardian_fault_barrier_v1(observed_name: &str, release_name: &str) {
    let Some(directory) =
        std::env::var_os("OXIDRA_INTERNAL_GUARDIAN_TEST_BARRIER_V1").map(PathBuf::from)
    else {
        return;
    };
    if std::fs::create_dir_all(&directory).is_err()
        || std::fs::write(directory.join(observed_name), b"observed").is_err()
    {
        return;
    }
    let release = directory.join(release_name);
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    while !release.is_file() && std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}

#[cfg(debug_assertions)]
fn publish_guardian_ready_for_fault_test_v1(process_id: u64) {
    let Some(directory) =
        std::env::var_os("OXIDRA_INTERNAL_GUARDIAN_TEST_BARRIER_V1").map(PathBuf::from)
    else {
        return;
    };
    let _ = std::fs::create_dir_all(&directory)
        .and_then(|()| std::fs::write(directory.join("guardian-ready"), process_id.to_string()));
}

#[cfg(all(debug_assertions, target_os = "linux"))]
fn linux_registration_fault_barrier_v1(process_id: u32) {
    if std::env::var_os("OXIDRA_INTERNAL_GUARDIAN_REGISTER_BARRIER_V1").as_deref()
        != Some(std::ffi::OsStr::new("1"))
    {
        return;
    }
    let Some(directory) =
        std::env::var_os("OXIDRA_INTERNAL_GUARDIAN_TEST_BARRIER_V1").map(PathBuf::from)
    else {
        return;
    };
    if std::fs::create_dir_all(&directory).is_err()
        || std::fs::write(
            directory.join("register-observed"),
            process_id.to_string().as_bytes(),
        )
        .is_err()
    {
        return;
    }
    let release = directory.join("allow-register");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    while !release.is_file() && std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}

#[cfg(all(not(debug_assertions), target_os = "linux"))]
fn linux_registration_fault_barrier_v1(_process_id: u32) {}

#[cfg(not(debug_assertions))]
fn guardian_fault_barrier_v1(_observed_name: &str, _release_name: &str) {}

#[cfg(target_os = "linux")]
fn linux_receive_registered_pidfd_v1(
    registration: &OwnedFd,
    expected_process_id: u32,
) -> io::Result<OwnedFd> {
    use std::mem::{size_of, zeroed};

    let mut frame = [0u8; FRAME_BYTES];
    let mut control = [0usize; 4];
    let mut iov = nix::libc::iovec {
        iov_base: frame.as_mut_ptr().cast(),
        iov_len: frame.len(),
    };
    let mut message: nix::libc::msghdr = unsafe { zeroed() };
    message.msg_iov = &raw mut iov;
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    message.msg_controllen = size_of::<[usize; 4]>();
    let received = loop {
        let result = unsafe {
            nix::libc::recvmsg(
                registration.as_raw_fd(),
                &raw mut message,
                nix::libc::MSG_CMSG_CLOEXEC,
            )
        };
        if result == -1 && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
            continue;
        }
        break result;
    };
    if received == -1 {
        return Err(io::Error::last_os_error());
    }

    let header = unsafe { nix::libc::CMSG_FIRSTHDR(&message) };
    let expected_header_bytes = unsafe { nix::libc::CMSG_LEN(size_of::<RawFd>() as u32) } as usize;
    let valid_header = !header.is_null()
        && unsafe {
            (*header).cmsg_level == nix::libc::SOL_SOCKET
                && (*header).cmsg_type == nix::libc::SCM_RIGHTS
                && (*header).cmsg_len == expected_header_bytes
        };
    let received_fd = if valid_header {
        Some(unsafe { nix::libc::CMSG_DATA(header).cast::<RawFd>().read() })
    } else {
        None
    };
    let next_header = if header.is_null() {
        std::ptr::null_mut()
    } else {
        unsafe { nix::libc::CMSG_NXTHDR(&message, header) }
    };
    let invalid = received != FRAME_BYTES as isize
        || message.msg_flags & (nix::libc::MSG_TRUNC | nix::libc::MSG_CTRUNC) != 0
        || !valid_header
        || !next_header.is_null()
        || !frame_matches_v1(&frame, FRAME_REGISTER, u64::from(expected_process_id))
        || received_fd.is_none_or(|fd| fd < 0);
    if invalid {
        if let Some(fd) = received_fd.filter(|fd| *fd >= 0) {
            let _ = unsafe { nix::libc::close(fd) };
        }
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid exact-pidfd registration from MCP pre-exec child",
        ));
    }
    Ok(unsafe { OwnedFd::from_raw_fd(received_fd.expect("validated Linux pidfd")) })
}

#[cfg(target_os = "linux")]
fn linux_terminate_and_wait_registered(registered: &[std::os::fd::OwnedFd]) {
    use std::os::fd::AsRawFd;
    use std::ptr;

    for pidfd in registered {
        let _ = unsafe {
            nix::libc::syscall(
                nix::libc::SYS_pidfd_send_signal,
                pidfd.as_raw_fd(),
                nix::libc::SIGKILL,
                ptr::null::<nix::libc::siginfo_t>(),
                0,
            )
        };
    }
    for pidfd in registered {
        let mut descriptor = nix::libc::pollfd {
            fd: pidfd.as_raw_fd(),
            events: nix::libc::POLLIN,
            revents: 0,
        };
        loop {
            let result = unsafe { nix::libc::poll(&mut descriptor, 1, -1) };
            if result > 0 && descriptor.revents & nix::libc::POLLIN != 0 {
                break;
            }
            if result == -1 && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
        }
    }
}

#[cfg(windows)]
struct WindowsHostProcessV1 {
    process: std::os::windows::io::OwnedHandle,
}

#[cfg(windows)]
impl WindowsHostProcessV1 {
    fn attach(host_pid: u32) -> Result<Self> {
        use std::os::windows::io::{FromRawHandle, OwnedHandle};
        use windows_sys::Win32::Foundation::{WAIT_OBJECT_0, WAIT_TIMEOUT};
        use windows_sys::Win32::System::Threading::{
            OpenProcess, PROCESS_DUP_HANDLE, WaitForSingleObject,
        };

        const SYNCHRONIZE: u32 = 0x0010_0000;

        ensure_windows_guardian_job_independence_v1()?;

        let raw_process = unsafe { OpenProcess(PROCESS_DUP_HANDLE | SYNCHRONIZE, 0, host_pid) };
        if raw_process.is_null() {
            return Err(io::Error::last_os_error().into());
        }
        let process = unsafe { OwnedHandle::from_raw_handle(raw_process.cast()) };
        match unsafe { WaitForSingleObject(raw_process, 0) } {
            WAIT_TIMEOUT => Ok(Self { process }),
            WAIT_OBJECT_0 => Err(OxidraError::Session(
                "MCP execution guardian host exited before readiness".to_owned(),
            )),
            _ => Err(io::Error::last_os_error().into()),
        }
    }

    fn spawn_process(
        &self,
        payload: &[u8],
    ) -> io::Result<crate::process::WindowsGuardianPreparedSpawnV1> {
        use std::os::windows::io::AsRawHandle;

        crate::process::windows_guardian_spawn_for_host_v1(payload, self.process.as_raw_handle())
    }

    fn close_remote_handles(&self, handles: &[u64]) {
        use std::os::windows::io::AsRawHandle;

        crate::process::windows_close_remote_handles_v1(self.process.as_raw_handle(), handles);
    }
}

#[cfg(windows)]
fn ensure_windows_guardian_job_independence_v1() -> Result<()> {
    use windows_sys::Win32::System::JobObjects::IsProcessInJob;
    use windows_sys::Win32::System::Threading::GetCurrentProcess;

    #[cfg(debug_assertions)]
    if std::env::var_os("OXIDRA_INTERNAL_GUARDIAN_ALLOW_SAME_JOB_V1").as_deref()
        == Some(std::ffi::OsStr::new("1"))
    {
        return Ok(());
    }

    let mut in_job = 0;
    let result = unsafe { IsProcessInJob(GetCurrentProcess(), std::ptr::null_mut(), &mut in_job) };
    if result == 0 {
        return Err(io::Error::last_os_error().into());
    }
    if in_job != 0 {
        return Err(OxidraError::Session(
            "MCP execution guardian remained inside a supervisor Job after breakaway".to_owned(),
        ));
    }
    Ok(())
}

#[cfg(windows)]
fn windows_error_code_v1(error: &io::Error) -> u64 {
    error
        .raw_os_error()
        .and_then(|value| u32::try_from(value).ok())
        .map(u64::from)
        .unwrap_or(0)
}

#[cfg(windows)]
fn windows_terminate_and_wait_registered(registered: &[std::os::windows::io::OwnedHandle]) {
    for job in registered {
        crate::process::windows_terminate_job_and_wait_empty_v1(job);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn execution_gate_active_record_remains_fail_closed_after_lock_release() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("execution.lock");
        let generation = *Uuid::now_v7().as_bytes();
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)
            .unwrap();
        append_execution_gate_state_v1(&mut file, GATE_STATE_ACTIVE_V1, generation).unwrap();
        drop(file);

        let error = ensure_execution_gate_quiescent_v1(&path).unwrap_err();
        assert!(error.to_string().contains("fail-closed"), "{error}");
        assert!(
            error
                .to_string()
                .contains("did not persist an exact containment-empty proof"),
            "{error}"
        );

        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .truncate(false)
            .open(&path)
            .unwrap();
        append_execution_gate_state_v1(&mut file, GATE_STATE_CLEAN_V1, generation).unwrap();
        drop(file);
        ensure_execution_gate_quiescent_v1(&path).unwrap();
    }

    #[test]
    fn execution_gate_torn_record_is_permanently_fail_closed() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("execution.lock");
        let record =
            encode_execution_gate_record_v1(GATE_STATE_ACTIVE_V1, *Uuid::now_v7().as_bytes());
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)
            .unwrap();
        file.write_all(&record[..GATE_STATE_RECORD_BYTES_V1 / 2])
            .unwrap();
        file.sync_all().unwrap();
        drop(file);

        let error = ensure_execution_gate_quiescent_v1(&path).unwrap_err();
        assert!(error.to_string().contains("incomplete record"), "{error}");
    }

    #[test]
    fn execution_gate_rejects_a_clean_record_without_matching_active_generation() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("execution.lock");
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)
            .unwrap();
        append_execution_gate_state_v1(&mut file, GATE_STATE_CLEAN_V1, *Uuid::now_v7().as_bytes())
            .unwrap();
        drop(file);

        let error = ensure_execution_gate_quiescent_v1(&path).unwrap_err();
        assert!(
            error.to_string().contains("generation state machine"),
            "{error}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn execution_gate_file_is_private_when_created_or_reopened() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("execution.lock");
        ensure_execution_gate_quiescent_v1(&path).unwrap();
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        ensure_execution_gate_quiescent_v1(&path).unwrap();
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}
