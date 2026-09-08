//! Cross-platform ownership and termination of spawned process trees.

use std::io;
use std::time::Duration;

#[cfg(windows)]
use std::collections::BTreeMap;
#[cfg(windows)]
use std::ffi::{OsStr, OsString};
#[cfg(windows)]
use std::path::Path;

use tokio::process::{Child, Command};

const PROCESS_EXIT_GRACE: Duration = Duration::from_secs(2);

#[cfg(windows)]
pub(crate) const WINDOWS_GUARDIAN_SPAWN_RESPONSE_BYTES_V1: usize = 6 * std::mem::size_of::<u64>();
#[cfg(windows)]
pub(crate) const MAX_WINDOWS_GUARDIAN_SPAWN_REQUEST_BYTES_V1: usize = 1024 * 1024;
#[cfg(windows)]
const WINDOWS_GUARDIAN_SPAWN_MAGIC_V1: [u8; 8] = *b"OXWSPN1\0";

pub(crate) struct ProcessTree {
    process_id: Option<u32>,
    #[cfg(target_os = "linux")]
    linux_contained: bool,
    #[cfg(target_os = "linux")]
    linux_pidfd: Option<std::os::fd::OwnedFd>,
    #[cfg(windows)]
    job: WindowsJob,
}

#[cfg(windows)]
pub(crate) struct WindowsContainedChildV1 {
    process: std::os::windows::io::OwnedHandle,
    exit_status: Option<std::process::ExitStatus>,
}

#[cfg(windows)]
pub(crate) struct WindowsContainedSpawnV1 {
    pub(crate) child: WindowsContainedChildV1,
    pub(crate) process_tree: ProcessTree,
    pub(crate) stdin: tokio::fs::File,
    pub(crate) stdout: tokio::fs::File,
    pub(crate) stderr: tokio::fs::File,
}

#[cfg(windows)]
pub(crate) struct WindowsGuardianPreparedSpawnV1 {
    pub(crate) job: std::os::windows::io::OwnedHandle,
    pub(crate) primary_thread: std::os::windows::io::OwnedHandle,
    pub(crate) remote_handles: [u64; 5],
    pub(crate) response: [u8; WINDOWS_GUARDIAN_SPAWN_RESPONSE_BYTES_V1],
}

pub(crate) trait ManagedChildV1 {
    fn start_kill_v1(&mut self) -> io::Result<()>;
    fn try_wait_v1(&mut self) -> io::Result<Option<std::process::ExitStatus>>;
}

impl ManagedChildV1 for Child {
    fn start_kill_v1(&mut self) -> io::Result<()> {
        self.start_kill()
    }

    fn try_wait_v1(&mut self) -> io::Result<Option<std::process::ExitStatus>> {
        self.try_wait()
    }
}

/// A clone-independent, exact-process termination capability retained by
/// cancellation guards that cannot await the asynchronous process owner.
///
/// MCP uses this handle after the child has been attached to its platform
/// containment primitive.  Signalling it is synchronous and therefore does
/// not depend on the Tokio runtime polling the task that owns `Child`.
pub(crate) struct ProcessTreeAbortHandle {
    #[cfg(target_os = "linux")]
    linux_pidfd: std::os::fd::OwnedFd,
    #[cfg(windows)]
    windows_job: std::os::windows::io::OwnedHandle,
}

impl ProcessTree {
    pub(crate) fn configure(command: &mut Command) {
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            command.as_std_mut().process_group(0);
        }
        #[cfg(not(unix))]
        let _ = command;
    }

    /// Configure an MCP child so no uncontained server code is started.
    ///
    /// Windows starts suspended and attaches a Job Object before resume. Linux
    /// installs a pre-exec seccomp policy that forbids process creation and
    /// process-group/session escape, binds the only server process to Oxidra
    /// with `PDEATHSIG`, and later opens a pidfd before protocol traffic. Other
    /// Unix targets fail closed until they have an equivalent kernel boundary.
    #[cfg(not(windows))]
    pub(crate) fn configure_suspended(command: &mut Command) -> io::Result<()> {
        Self::configure(command);
        #[cfg(target_os = "linux")]
        linux_containment::prepare(command)?;
        #[cfg(all(unix, not(target_os = "linux")))]
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "MCP descendant containment is not implemented for this Unix platform",
        ));
        Ok(())
    }

    /// Attach ownership immediately after spawn, before any protocol traffic is
    /// sent. Ordinary Unix children use a process group; Linux MCP children use
    /// the stronger pre-exec policy plus a pidfd, and Windows uses a Job Object.
    pub(crate) fn attach(child: &Child) -> io::Result<Self> {
        Self::attach_with_containment(child, false)
    }

    /// Attach the stronger ownership mode required by long-lived MCP servers.
    #[cfg(not(windows))]
    pub(crate) fn attach_contained(child: &Child) -> io::Result<Self> {
        Self::attach_with_containment(child, true)
    }

    fn attach_with_containment(child: &Child, contained: bool) -> io::Result<Self> {
        let process_id = child.id().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                "child exited before process-tree ownership was established",
            )
        })?;
        #[cfg(target_os = "linux")]
        let linux_pidfd = if contained {
            Some(linux_containment::open_pidfd(process_id)?)
        } else {
            None
        };
        #[cfg(not(target_os = "linux"))]
        let _ = contained;
        #[cfg(windows)]
        let job = WindowsJob::attach(child)?;
        Ok(Self {
            process_id: Some(process_id),
            #[cfg(target_os = "linux")]
            linux_contained: contained,
            #[cfg(target_os = "linux")]
            linux_pidfd,
            #[cfg(windows)]
            job,
        })
    }

    /// Resume a child created by `configure_suspended` only after process-tree
    /// ownership and all stdio drains have been established.
    #[cfg(not(windows))]
    pub(crate) fn resume_suspended(&mut self) -> io::Result<()> {
        Ok(())
    }

    /// Duplicate the native containment identity for synchronous cancellation.
    ///
    /// Unsupported Unix platforms already fail closed in
    /// `configure_suspended`; keep this method fail-closed as well so adding a
    /// new launch path cannot silently fall back to a numeric PID.
    pub(crate) fn abort_handle(&self) -> io::Result<ProcessTreeAbortHandle> {
        #[cfg(target_os = "linux")]
        {
            if !self.linux_contained {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "exact synchronous abort requires Linux MCP containment",
                ));
            }
            let pidfd = self.linux_pidfd.as_ref().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    "contained Linux process has no pidfd",
                )
            })?;
            Ok(ProcessTreeAbortHandle {
                linux_pidfd: pidfd.try_clone()?,
            })
        }
        #[cfg(all(unix, not(target_os = "linux")))]
        {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "exact synchronous abort is not implemented for this Unix platform",
            ))
        }
        #[cfg(windows)]
        {
            Ok(ProcessTreeAbortHandle {
                windows_job: self.job.handle.try_clone()?,
            })
        }
    }

    /// Kill the complete group/job even when its leader has already exited.
    pub(crate) fn terminate_descendants(&mut self) {
        let process_id = self.process_id.take();
        #[cfg(target_os = "linux")]
        if let Some(process_id) = process_id {
            if self.linux_contained {
                if let Some(pidfd) = &self.linux_pidfd {
                    linux_containment::signal_pidfd(pidfd, nix::libc::SIGKILL);
                }
            } else {
                use nix::sys::signal::{Signal, killpg};
                use nix::unistd::Pid;
                let _ = killpg(Pid::from_raw(process_id as i32), Signal::SIGKILL);
            }
        }
        #[cfg(all(unix, not(target_os = "linux")))]
        if let Some(process_id) = process_id {
            use nix::sys::signal::{Signal, killpg};
            use nix::unistd::Pid;
            let _ = killpg(Pid::from_raw(process_id as i32), Signal::SIGKILL);
        }
        #[cfg(windows)]
        {
            let _ = process_id;
            self.job.terminate();
        }
    }

    pub(crate) async fn terminate(&mut self, child: &mut Child) {
        self.terminate_descendants();
        if !matches!(child.try_wait(), Ok(Some(_))) {
            let _ = child.start_kill();
        }
        let _ = tokio::time::timeout(PROCESS_EXIT_GRACE, child.wait()).await;
    }

    /// Terminate and synchronously reap a contained child without depending
    /// on an async runtime. This operation intentionally has no timeout: the
    /// caller must retain its execution lease until the OS proves that both
    /// the direct process and the complete native containment are gone.
    pub(crate) fn terminate_and_reap_blocking<C: ManagedChildV1>(&mut self, child: &mut C) {
        self.terminate_descendants();
        let _ = child.start_kill_v1();
        loop {
            match child.try_wait_v1() {
                Ok(Some(_)) => break,
                Ok(None) | Err(_) => {
                    self.terminate_descendants();
                    let _ = child.start_kill_v1();
                    std::thread::sleep(Duration::from_millis(20));
                }
            }
        }
        self.terminate_descendants();
        self.wait_containment_empty_blocking();
    }

    /// Block until the platform containment contains no live process.
    ///
    /// The MCP transport reaper calls this only after it has requested
    /// termination and synchronously reaped the direct child. Linux MCP
    /// servers cannot create descendant processes under the frozen seccomp
    /// profile, so the direct-child wait is sufficient there. A Windows Job
    /// Object may still contain descendants after the leader exits, and its
    /// signalled state is the kernel proof that the complete job is empty.
    pub(crate) fn wait_containment_empty_blocking(&self) {
        #[cfg(windows)]
        self.job.wait_empty_blocking();
        #[cfg(not(windows))]
        let _ = self;
    }
}

impl ProcessTreeAbortHandle {
    /// Best-effort synchronous termination of the exact contained process.
    /// Async ownership remains responsible for the eventual wait/reap.
    pub(crate) fn abort(&self) {
        #[cfg(target_os = "linux")]
        linux_containment::signal_pidfd(&self.linux_pidfd, nix::libc::SIGKILL);
        #[cfg(windows)]
        {
            use std::os::windows::io::AsRawHandle;
            use windows_sys::Win32::System::JobObjects::TerminateJobObject;

            let _ = unsafe { TerminateJobObject(self.windows_job.as_raw_handle().cast(), 1) };
        }
    }
}

#[cfg(windows)]
impl ManagedChildV1 for WindowsContainedChildV1 {
    fn start_kill_v1(&mut self) -> io::Result<()> {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::System::Threading::TerminateProcess;

        if self.try_wait_v1()?.is_some() {
            return Ok(());
        }
        let terminated = unsafe { TerminateProcess(self.process.as_raw_handle().cast(), 1) };
        if terminated == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    fn try_wait_v1(&mut self) -> io::Result<Option<std::process::ExitStatus>> {
        use std::os::windows::io::AsRawHandle;
        use std::os::windows::process::ExitStatusExt;
        use windows_sys::Win32::Foundation::{WAIT_OBJECT_0, WAIT_TIMEOUT};
        use windows_sys::Win32::System::Threading::{GetExitCodeProcess, WaitForSingleObject};

        if let Some(status) = self.exit_status {
            return Ok(Some(status));
        }
        match unsafe { WaitForSingleObject(self.process.as_raw_handle().cast(), 0) } {
            WAIT_TIMEOUT => Ok(None),
            WAIT_OBJECT_0 => {
                let mut exit_code = 0;
                if unsafe {
                    GetExitCodeProcess(self.process.as_raw_handle().cast(), &mut exit_code)
                } == 0
                {
                    return Err(io::Error::last_os_error());
                }
                let status = std::process::ExitStatus::from_raw(exit_code);
                self.exit_status = Some(status);
                Ok(Some(status))
            }
            _ => Err(io::Error::last_os_error()),
        }
    }
}

#[cfg(windows)]
pub(crate) fn windows_guardian_spawn_request_v1(
    command: &Path,
    args: &[String],
    cwd: Option<&Path>,
    inherited_env: &BTreeMap<String, OsString>,
    explicit_env: &BTreeMap<String, String>,
) -> io::Result<Vec<u8>> {
    use std::mem::size_of;

    let application = nul_terminated_wide_v1(command.as_os_str(), "MCP executable path")?;
    let command_line = windows_command_line_v1(command.as_os_str(), args)?;
    let environment = windows_environment_block_v1(inherited_env, explicit_env)?;
    let cwd = cwd
        .map(|path| nul_terminated_wide_v1(path.as_os_str(), "MCP working directory"))
        .transpose()?
        .unwrap_or_default();
    let fields = [&application, &command_line, &cwd, &environment];
    let header_bytes = WINDOWS_GUARDIAN_SPAWN_MAGIC_V1.len() + fields.len() * size_of::<u32>();
    let payload_bytes = fields.iter().try_fold(header_bytes, |total, field| {
        total.checked_add(field.len().checked_mul(size_of::<u16>())?)
    });
    let payload_bytes = payload_bytes.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "Windows MCP guardian spawn request is too large",
        )
    })?;
    if payload_bytes > MAX_WINDOWS_GUARDIAN_SPAWN_REQUEST_BYTES_V1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Windows MCP guardian spawn request exceeds its byte limit",
        ));
    }
    let mut payload = Vec::with_capacity(payload_bytes);
    payload.extend_from_slice(&WINDOWS_GUARDIAN_SPAWN_MAGIC_V1);
    for field in fields {
        let units = u32::try_from(field.len()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "Windows MCP guardian spawn field is too large",
            )
        })?;
        payload.extend_from_slice(&units.to_le_bytes());
    }
    for field in fields {
        for unit in field {
            payload.extend_from_slice(&unit.to_le_bytes());
        }
    }
    Ok(payload)
}

#[cfg(windows)]
pub(crate) fn windows_guardian_spawn_for_host_v1(
    payload: &[u8],
    host_process: std::os::windows::io::RawHandle,
) -> io::Result<WindowsGuardianPreparedSpawnV1> {
    use std::mem::{size_of, zeroed};
    use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
    use windows_sys::Win32::Foundation::HANDLE;
    use windows_sys::Win32::System::Threading::{
        CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, CreateProcessW, EXTENDED_STARTUPINFO_PRESENT,
        PROC_THREAD_ATTRIBUTE_HANDLE_LIST, PROC_THREAD_ATTRIBUTE_JOB_LIST, PROCESS_INFORMATION,
        STARTF_USESTDHANDLES, STARTUPINFOEXW,
    };

    let spec = decode_windows_guardian_spawn_request_v1(payload)?;
    let job_handle = windows_create_kill_on_close_job_v1()?;
    let (child_stdin, parent_stdin) = windows_pipe_pair_v1()?;
    let (parent_stdout, child_stdout) = windows_pipe_pair_v1()?;
    let (parent_stderr, child_stderr) = windows_pipe_pair_v1()?;

    let inherited_handles: [HANDLE; 3] = [
        child_stdin.as_raw_handle().cast(),
        child_stdout.as_raw_handle().cast(),
        child_stderr.as_raw_handle().cast(),
    ];
    let job_handles: [HANDLE; 1] = [job_handle.as_raw_handle().cast()];
    let mut attributes = ProcThreadAttributeListV1::new(2)?;
    attributes.update(
        PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
        inherited_handles.as_ptr().cast(),
        size_of::<[HANDLE; 3]>(),
    )?;
    attributes.update(
        PROC_THREAD_ATTRIBUTE_JOB_LIST as usize,
        job_handles.as_ptr().cast(),
        size_of::<[HANDLE; 1]>(),
    )?;

    let mut startup: STARTUPINFOEXW = unsafe { zeroed() };
    startup.StartupInfo.cb = size_of::<STARTUPINFOEXW>() as u32;
    startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    startup.StartupInfo.hStdInput = inherited_handles[0];
    startup.StartupInfo.hStdOutput = inherited_handles[1];
    startup.StartupInfo.hStdError = inherited_handles[2];
    startup.lpAttributeList = attributes.as_ptr();
    let mut process_information: PROCESS_INFORMATION = unsafe { zeroed() };

    // The guardian is a dedicated single-threaded process and never performs
    // a second concurrent CreateProcess. This is the only place where its
    // pipe ends temporarily become inheritable, eliminating the host-wide
    // inheritance race with std/tokio/third-party process creation.
    let inheritable = TemporarilyInheritableHandlesV1::new(&inherited_handles)?;
    let mut command_line = spec.command_line;
    let created = unsafe {
        CreateProcessW(
            spec.application.as_ptr(),
            command_line.as_mut_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            1,
            CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT | EXTENDED_STARTUPINFO_PRESENT,
            spec.environment.as_ptr().cast(),
            if spec.cwd.is_empty() {
                std::ptr::null()
            } else {
                spec.cwd.as_ptr()
            },
            (&raw const startup).cast(),
            &mut process_information,
        )
    };
    drop(inheritable);
    drop(child_stdin);
    drop(child_stdout);
    drop(child_stderr);
    if created == 0 {
        return Err(io::Error::last_os_error());
    }

    let process = unsafe { OwnedHandle::from_raw_handle(process_information.hProcess.cast()) };
    let primary_thread =
        unsafe { OwnedHandle::from_raw_handle(process_information.hThread.cast()) };
    let process_id = process_information.dwProcessId;
    let remote_handles = match duplicate_handles_to_process_v1(
        &[
            job_handle.as_raw_handle().cast(),
            process.as_raw_handle().cast(),
            parent_stdin.as_raw_handle().cast(),
            parent_stdout.as_raw_handle().cast(),
            parent_stderr.as_raw_handle().cast(),
        ],
        host_process.cast(),
    ) {
        Ok(handles) => handles,
        Err(error) => {
            windows_terminate_job_and_wait_empty_v1(&job_handle);
            return Err(error);
        }
    };
    let mut response = [0u8; WINDOWS_GUARDIAN_SPAWN_RESPONSE_BYTES_V1];
    for (index, value) in remote_handles
        .into_iter()
        .chain([u64::from(process_id)])
        .enumerate()
    {
        let offset = index * size_of::<u64>();
        response[offset..offset + size_of::<u64>()].copy_from_slice(&value.to_le_bytes());
    }
    Ok(WindowsGuardianPreparedSpawnV1 {
        job: job_handle,
        primary_thread,
        remote_handles,
        response,
    })
}

#[cfg(windows)]
pub(crate) fn windows_contained_spawn_from_guardian_response_v1(
    response: &[u8; WINDOWS_GUARDIAN_SPAWN_RESPONSE_BYTES_V1],
) -> io::Result<WindowsContainedSpawnV1> {
    use std::mem::size_of;
    use std::os::windows::io::{FromRawHandle, OwnedHandle};

    let mut values = [0u64; 6];
    for (index, slot) in values.iter_mut().enumerate() {
        let offset = index * size_of::<u64>();
        *slot = u64::from_le_bytes(
            response[offset..offset + size_of::<u64>()]
                .try_into()
                .expect("fixed Windows guardian response chunk"),
        );
    }
    if values[..5].contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Windows guardian returned a null process handle",
        ));
    }
    let process_id = u32::try_from(values[5])
        .ok()
        .filter(|value| *value != 0)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "Windows guardian returned an invalid process id",
            )
        })?;
    let raw = |value: u64| -> io::Result<*mut std::ffi::c_void> {
        let value = usize::try_from(value).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "Windows guardian handle does not fit the host pointer width",
            )
        })?;
        Ok(value as *mut std::ffi::c_void)
    };
    let job = unsafe { OwnedHandle::from_raw_handle(raw(values[0])?) };
    let process = unsafe { OwnedHandle::from_raw_handle(raw(values[1])?) };
    let stdin = unsafe { std::fs::File::from_raw_handle(raw(values[2])?) };
    let stdout = unsafe { std::fs::File::from_raw_handle(raw(values[3])?) };
    let stderr = unsafe { std::fs::File::from_raw_handle(raw(values[4])?) };
    Ok(WindowsContainedSpawnV1 {
        child: WindowsContainedChildV1 {
            process,
            exit_status: None,
        },
        process_tree: ProcessTree {
            process_id: Some(process_id),
            job: WindowsJob { handle: job },
        },
        stdin: tokio::fs::File::from_std(stdin),
        stdout: tokio::fs::File::from_std(stdout),
        stderr: tokio::fs::File::from_std(stderr),
    })
}

#[cfg(windows)]
struct WindowsGuardianSpawnSpecV1 {
    application: Vec<u16>,
    command_line: Vec<u16>,
    cwd: Vec<u16>,
    environment: Vec<u16>,
}

#[cfg(windows)]
fn decode_windows_guardian_spawn_request_v1(
    payload: &[u8],
) -> io::Result<WindowsGuardianSpawnSpecV1> {
    use std::mem::size_of;

    if payload.len() > MAX_WINDOWS_GUARDIAN_SPAWN_REQUEST_BYTES_V1
        || payload.len() < WINDOWS_GUARDIAN_SPAWN_MAGIC_V1.len() + 4 * size_of::<u32>()
        || payload[..WINDOWS_GUARDIAN_SPAWN_MAGIC_V1.len()] != WINDOWS_GUARDIAN_SPAWN_MAGIC_V1
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid Windows MCP guardian spawn request header",
        ));
    }
    let mut cursor = WINDOWS_GUARDIAN_SPAWN_MAGIC_V1.len();
    let mut lengths = [0usize; 4];
    for length in &mut lengths {
        let end = cursor + size_of::<u32>();
        *length = u32::from_le_bytes(
            payload[cursor..end]
                .try_into()
                .expect("checked Windows guardian request header"),
        ) as usize;
        cursor = end;
    }
    let expected = lengths.iter().try_fold(cursor, |total, units| {
        total.checked_add(units.checked_mul(size_of::<u16>())?)
    });
    if expected != Some(payload.len()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid Windows MCP guardian spawn request length",
        ));
    }
    let mut fields = Vec::with_capacity(lengths.len());
    for units in lengths {
        let mut field = Vec::with_capacity(units);
        for _ in 0..units {
            let end = cursor + size_of::<u16>();
            field.push(u16::from_le_bytes(
                payload[cursor..end]
                    .try_into()
                    .expect("checked Windows guardian request field"),
            ));
            cursor = end;
        }
        fields.push(field);
    }
    let [application, command_line, cwd, environment]: [Vec<u16>; 4] = fields
        .try_into()
        .expect("four Windows guardian spawn request fields");
    validate_single_nul_terminated_wide_v1(&application, "application")?;
    validate_single_nul_terminated_wide_v1(&command_line, "command line")?;
    if !cwd.is_empty() {
        validate_single_nul_terminated_wide_v1(&cwd, "working directory")?;
    }
    if environment.len() < 2
        || environment[environment.len() - 2..] != [0, 0]
        || environment[..environment.len() - 2]
            .windows(2)
            .any(|pair| pair == [0, 0])
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid Windows MCP guardian environment block",
        ));
    }
    Ok(WindowsGuardianSpawnSpecV1 {
        application,
        command_line,
        cwd,
        environment,
    })
}

#[cfg(windows)]
fn validate_single_nul_terminated_wide_v1(value: &[u16], label: &str) -> io::Result<()> {
    if value.last() != Some(&0) || value[..value.len().saturating_sub(1)].contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid Windows MCP guardian {label}"),
        ));
    }
    Ok(())
}

#[cfg(windows)]
fn duplicate_handles_to_process_v1<const N: usize>(
    handles: &[windows_sys::Win32::Foundation::HANDLE; N],
    target_process: windows_sys::Win32::Foundation::HANDLE,
) -> io::Result<[u64; N]> {
    use windows_sys::Win32::Foundation::{
        CloseHandle, DUPLICATE_CLOSE_SOURCE, DUPLICATE_SAME_ACCESS, DuplicateHandle, HANDLE,
    };
    use windows_sys::Win32::System::Threading::GetCurrentProcess;

    let mut duplicated = [0u64; N];
    for (index, source) in handles.iter().enumerate() {
        let mut remote: HANDLE = std::ptr::null_mut();
        let result = unsafe {
            DuplicateHandle(
                GetCurrentProcess(),
                *source,
                target_process,
                &mut remote,
                0,
                0,
                DUPLICATE_SAME_ACCESS,
            )
        };
        if result == 0 || remote.is_null() {
            let error = io::Error::last_os_error();
            for value in duplicated[..index]
                .iter()
                .copied()
                .filter(|value| *value != 0)
            {
                let mut local: HANDLE = std::ptr::null_mut();
                let _ = unsafe {
                    DuplicateHandle(
                        target_process,
                        value as usize as HANDLE,
                        GetCurrentProcess(),
                        &mut local,
                        0,
                        0,
                        DUPLICATE_CLOSE_SOURCE | DUPLICATE_SAME_ACCESS,
                    )
                };
                if !local.is_null() {
                    let _ = unsafe { CloseHandle(local) };
                }
            }
            return Err(error);
        }
        duplicated[index] = remote as usize as u64;
    }
    Ok(duplicated)
}

#[cfg(windows)]
pub(crate) fn windows_close_remote_handles_v1(
    source_process: std::os::windows::io::RawHandle,
    handles: &[u64],
) {
    use windows_sys::Win32::Foundation::{
        CloseHandle, DUPLICATE_CLOSE_SOURCE, DUPLICATE_SAME_ACCESS, DuplicateHandle, HANDLE,
    };
    use windows_sys::Win32::System::Threading::GetCurrentProcess;

    for value in handles.iter().copied().filter(|value| *value != 0) {
        let Ok(value) = usize::try_from(value) else {
            continue;
        };
        let mut local: HANDLE = std::ptr::null_mut();
        let _ = unsafe {
            DuplicateHandle(
                source_process.cast(),
                value as HANDLE,
                GetCurrentProcess(),
                &mut local,
                0,
                0,
                DUPLICATE_CLOSE_SOURCE | DUPLICATE_SAME_ACCESS,
            )
        };
        if !local.is_null() {
            let _ = unsafe { CloseHandle(local) };
        }
    }
}

#[cfg(windows)]
pub(crate) fn windows_resume_guardian_spawn_v1(
    primary_thread: &std::os::windows::io::OwnedHandle,
) -> io::Result<()> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::System::Threading::ResumeThread;

    let previous = unsafe { ResumeThread(primary_thread.as_raw_handle().cast()) };
    if previous == u32::MAX {
        return Err(io::Error::last_os_error());
    }
    if previous != 1 {
        return Err(io::Error::other(format!(
            "MCP child thread had unexpected suspend count {previous}"
        )));
    }
    Ok(())
}

#[cfg(windows)]
pub(crate) fn windows_create_kill_on_close_job_v1() -> io::Result<std::os::windows::io::OwnedHandle>
{
    use std::ffi::c_void;
    use std::mem::{size_of, zeroed};
    use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
    use windows_sys::Win32::System::JobObjects::{
        CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
        JobObjectExtendedLimitInformation, SetInformationJobObject,
    };

    let raw_job = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
    if raw_job.is_null() {
        return Err(io::Error::last_os_error());
    }
    let job = unsafe { OwnedHandle::from_raw_handle(raw_job.cast()) };
    let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { zeroed() };
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    let configured = unsafe {
        SetInformationJobObject(
            job.as_raw_handle().cast(),
            JobObjectExtendedLimitInformation,
            (&raw const limits).cast::<c_void>(),
            size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
        )
    };
    if configured == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(job)
}

#[cfg(windows)]
pub(crate) fn windows_terminate_job_and_wait_empty_v1(job: &std::os::windows::io::OwnedHandle) {
    use std::mem::{size_of, zeroed};
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::System::JobObjects::{
        JOBOBJECT_BASIC_ACCOUNTING_INFORMATION, JobObjectBasicAccountingInformation,
        QueryInformationJobObject, TerminateJobObject,
    };

    let _ = unsafe { TerminateJobObject(job.as_raw_handle().cast(), 1) };
    loop {
        let mut accounting: JOBOBJECT_BASIC_ACCOUNTING_INFORMATION = unsafe { zeroed() };
        let queried = unsafe {
            QueryInformationJobObject(
                job.as_raw_handle().cast(),
                JobObjectBasicAccountingInformation,
                (&raw mut accounting).cast(),
                size_of::<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION>() as u32,
                std::ptr::null_mut(),
            )
        };
        if queried != 0 && accounting.ActiveProcesses == 0 {
            return;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[cfg(windows)]
fn windows_pipe_pair_v1() -> io::Result<(
    std::os::windows::io::OwnedHandle,
    std::os::windows::io::OwnedHandle,
)> {
    use std::mem::{size_of, zeroed};
    use std::os::windows::io::{FromRawHandle, OwnedHandle};
    use windows_sys::Win32::Foundation::HANDLE;
    use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn CreatePipe(
            read_pipe: *mut HANDLE,
            write_pipe: *mut HANDLE,
            attributes: *const SECURITY_ATTRIBUTES,
            size: u32,
        ) -> i32;
    }

    let mut attributes: SECURITY_ATTRIBUTES = unsafe { zeroed() };
    attributes.nLength = size_of::<SECURITY_ATTRIBUTES>() as u32;
    // Both pipe ends start non-inheritable. Only the three child ends are
    // temporarily marked inheritable around the exact CreateProcessW call.
    attributes.bInheritHandle = 0;
    let mut read = std::ptr::null_mut();
    let mut write = std::ptr::null_mut();
    if unsafe { CreatePipe(&mut read, &mut write, &attributes, 0) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let read = unsafe { OwnedHandle::from_raw_handle(read.cast()) };
    let write = unsafe { OwnedHandle::from_raw_handle(write.cast()) };
    Ok((read, write))
}

#[cfg(windows)]
struct ProcThreadAttributeListV1 {
    storage: Vec<usize>,
    initialized: bool,
}

#[cfg(windows)]
impl ProcThreadAttributeListV1 {
    fn new(attribute_count: u32) -> io::Result<Self> {
        use windows_sys::Win32::System::Threading::InitializeProcThreadAttributeList;

        let mut bytes = 0usize;
        unsafe {
            InitializeProcThreadAttributeList(std::ptr::null_mut(), attribute_count, 0, &mut bytes);
        }
        if bytes == 0 {
            return Err(io::Error::last_os_error());
        }
        let words = bytes.div_ceil(size_of::<usize>());
        let mut list = Self {
            storage: vec![0usize; words],
            initialized: false,
        };
        if unsafe {
            InitializeProcThreadAttributeList(list.as_ptr(), attribute_count, 0, &mut bytes)
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        list.initialized = true;
        Ok(list)
    }

    fn as_ptr(&mut self) -> windows_sys::Win32::System::Threading::LPPROC_THREAD_ATTRIBUTE_LIST {
        self.storage.as_mut_ptr().cast()
    }

    fn update(
        &mut self,
        attribute: usize,
        value: *const std::ffi::c_void,
        bytes: usize,
    ) -> io::Result<()> {
        use windows_sys::Win32::System::Threading::UpdateProcThreadAttribute;

        if unsafe {
            UpdateProcThreadAttribute(
                self.as_ptr(),
                0,
                attribute,
                value,
                bytes,
                std::ptr::null_mut(),
                std::ptr::null(),
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

#[cfg(windows)]
impl Drop for ProcThreadAttributeListV1 {
    fn drop(&mut self) {
        use windows_sys::Win32::System::Threading::DeleteProcThreadAttributeList;

        if self.initialized {
            unsafe { DeleteProcThreadAttributeList(self.as_ptr()) };
        }
    }
}

#[cfg(windows)]
struct TemporarilyInheritableHandlesV1<'a> {
    handles: &'a [windows_sys::Win32::Foundation::HANDLE],
}

#[cfg(windows)]
impl<'a> TemporarilyInheritableHandlesV1<'a> {
    fn new(handles: &'a [windows_sys::Win32::Foundation::HANDLE]) -> io::Result<Self> {
        use windows_sys::Win32::Foundation::{HANDLE_FLAG_INHERIT, SetHandleInformation};

        for (index, handle) in handles.iter().enumerate() {
            let configured =
                unsafe { SetHandleInformation(*handle, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT) };
            if configured == 0 {
                for configured_handle in &handles[..index] {
                    let _ =
                        unsafe { SetHandleInformation(*configured_handle, HANDLE_FLAG_INHERIT, 0) };
                }
                return Err(io::Error::last_os_error());
            }
        }
        Ok(Self { handles })
    }
}

#[cfg(windows)]
impl Drop for TemporarilyInheritableHandlesV1<'_> {
    fn drop(&mut self) {
        use windows_sys::Win32::Foundation::{HANDLE_FLAG_INHERIT, SetHandleInformation};

        for handle in self.handles {
            let _ = unsafe { SetHandleInformation(*handle, HANDLE_FLAG_INHERIT, 0) };
        }
    }
}

#[cfg(windows)]
fn nul_terminated_wide_v1(value: &OsStr, label: &str) -> io::Result<Vec<u16>> {
    use std::os::windows::ffi::OsStrExt;

    let mut wide = value.encode_wide().collect::<Vec<_>>();
    if wide.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{label} contains an interior NUL"),
        ));
    }
    wide.push(0);
    Ok(wide)
}

#[cfg(windows)]
fn windows_command_line_v1(command: &OsStr, args: &[String]) -> io::Result<Vec<u16>> {
    let mut command_line = Vec::new();
    append_windows_argument_v1(&mut command_line, command)?;
    for argument in args {
        command_line.push(' ' as u16);
        append_windows_argument_v1(&mut command_line, OsStr::new(argument))?;
    }
    command_line.push(0);
    Ok(command_line)
}

#[cfg(windows)]
fn append_windows_argument_v1(output: &mut Vec<u16>, argument: &OsStr) -> io::Result<()> {
    use std::os::windows::ffi::OsStrExt;

    let argument = argument.encode_wide().collect::<Vec<_>>();
    if argument.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "MCP argument contains an interior NUL",
        ));
    }
    let quote = argument.is_empty()
        || argument
            .iter()
            .any(|value| *value == b' ' as u16 || *value == b'\t' as u16 || *value == b'"' as u16);
    if !quote {
        output.extend_from_slice(&argument);
        return Ok(());
    }
    output.push(b'"' as u16);
    let mut backslashes = 0usize;
    for value in argument {
        if value == b'\\' as u16 {
            backslashes += 1;
            continue;
        }
        if value == b'"' as u16 {
            output.extend(std::iter::repeat_n(b'\\' as u16, backslashes * 2 + 1));
            output.push(value);
        } else {
            output.extend(std::iter::repeat_n(b'\\' as u16, backslashes));
            output.push(value);
        }
        backslashes = 0;
    }
    output.extend(std::iter::repeat_n(b'\\' as u16, backslashes * 2));
    output.push(b'"' as u16);
    Ok(())
}

#[cfg(windows)]
fn windows_environment_block_v1(
    inherited_env: &BTreeMap<String, OsString>,
    explicit_env: &BTreeMap<String, String>,
) -> io::Result<Vec<u16>> {
    use std::os::windows::ffi::OsStrExt;

    let mut values = BTreeMap::<String, (String, OsString)>::new();
    for (name, value) in inherited_env {
        values.insert(name.to_ascii_uppercase(), (name.clone(), value.clone()));
    }
    for (name, value) in explicit_env {
        values.insert(
            name.to_ascii_uppercase(),
            (name.clone(), OsString::from(value)),
        );
    }
    let mut block = Vec::new();
    for (_, (name, value)) in values {
        let mut entry = OsString::from(name);
        entry.push("=");
        entry.push(value);
        let encoded = entry.encode_wide().collect::<Vec<_>>();
        if encoded.contains(&0) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "MCP environment contains an interior NUL",
            ));
        }
        block.extend(encoded);
        block.push(0);
    }
    if block.is_empty() {
        block.push(0);
    }
    block.push(0);
    Ok(block)
}

#[cfg(all(test, windows))]
mod windows_tests {
    use std::collections::BTreeMap;
    use std::ffi::{OsStr, OsString};
    use std::os::windows::ffi::{OsStrExt, OsStringExt};
    use std::path::PathBuf;

    use super::{
        decode_windows_guardian_spawn_request_v1, windows_command_line_v1,
        windows_guardian_spawn_request_v1,
    };

    #[test]
    fn guardian_spawn_request_preserves_windows_native_code_units() {
        let command = PathBuf::from(OsString::from_wide(&[
            b'C' as u16,
            b':' as u16,
            b'\\' as u16,
            0xd800,
            b'.' as u16,
            b'e' as u16,
            b'x' as u16,
            b'e' as u16,
        ]));
        let cwd = PathBuf::from(OsString::from_wide(&[
            b'C' as u16,
            b':' as u16,
            b'\\' as u16,
            0xdfff,
        ]));
        let mut inherited = BTreeMap::new();
        inherited.insert(
            "SECRET".to_owned(),
            OsString::from_wide(&[b'x' as u16, 0xd801, b'y' as u16]),
        );
        let payload = windows_guardian_spawn_request_v1(
            &command,
            &["two words".to_owned()],
            Some(&cwd),
            &inherited,
            &BTreeMap::new(),
        )
        .expect("encode guardian spawn request");
        let decoded = decode_windows_guardian_spawn_request_v1(&payload)
            .expect("decode guardian spawn request");

        let mut expected_command = command.as_os_str().encode_wide().collect::<Vec<_>>();
        expected_command.push(0);
        let mut expected_cwd = cwd.as_os_str().encode_wide().collect::<Vec<_>>();
        expected_cwd.push(0);
        assert_eq!(decoded.application, expected_command);
        assert_eq!(decoded.cwd, expected_cwd);
        assert!(decoded.environment.contains(&0xd801));
    }

    #[test]
    fn windows_command_line_quotes_empty_spaces_quotes_and_trailing_slashes() {
        let encoded = windows_command_line_v1(
            OsStr::new(r"C:\Program Files\server.exe"),
            &[
                String::new(),
                "plain".to_owned(),
                "two words".to_owned(),
                "space slash\\".to_owned(),
                "quote\"here".to_owned(),
            ],
        )
        .expect("encode Windows command line");
        let actual = String::from_utf16(&encoded[..encoded.len() - 1])
            .expect("command line contains valid fixture UTF-16");
        assert_eq!(
            actual,
            r#""C:\Program Files\server.exe" "" plain "two words" "space slash\\" "quote\"here""#
        );
    }
}

#[cfg(target_os = "linux")]
mod linux_containment {
    use std::io;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::os::unix::process::CommandExt;
    use std::ptr;

    use nix::libc;
    use tokio::process::Command;

    const BPF_LD_W_ABS: u16 = 0x20;
    const BPF_ALU_AND_K: u16 = 0x54;
    const BPF_JMP_JEQ_K: u16 = 0x15;
    const BPF_JMP_JSET_K: u16 = 0x45;
    const BPF_RET_K: u16 = 0x06;
    const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;
    const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
    const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
    const SECCOMP_SET_MODE_FILTER: libc::c_uint = 1;
    const SECCOMP_DATA_NR_OFFSET: u32 = 0;
    const SECCOMP_DATA_ARCH_OFFSET: u32 = 4;
    const SECCOMP_DATA_ARG0_OFFSET: u32 = 16;

    pub(super) fn prepare(command: &mut Command) -> io::Result<()> {
        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        {
            let _ = command;
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "MCP Linux containment supports only x86_64 and aarch64",
            ));
        }

        #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
        {
            // Probe the required identity primitive before any untrusted MCP
            // code executes. The real child pidfd is opened immediately after
            // spawn, while the child is still an unreaped process and cannot
            // have its PID reused.
            let probe = open_pidfd(unsafe { libc::getpid() } as u32)?;
            drop(probe);
            let owner = unsafe { libc::getpid() };
            let mut filter = process_policy_filter();
            let filter_len = u16::try_from(filter.len()).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "seccomp filter is too large")
            })?;
            unsafe {
                command.as_std_mut().pre_exec(move || {
                    if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) == -1 {
                        return Err(io::Error::last_os_error());
                    }
                    if libc::getppid() != owner {
                        libc::_exit(127);
                    }
                    if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == -1 {
                        return Err(io::Error::last_os_error());
                    }
                    let program = libc::sock_fprog {
                        len: filter_len,
                        filter: filter.as_mut_ptr(),
                    };
                    if libc::syscall(
                        libc::SYS_seccomp,
                        SECCOMP_SET_MODE_FILTER,
                        0,
                        &raw const program,
                    ) == -1
                    {
                        return Err(io::Error::last_os_error());
                    }
                    if libc::getppid() != owner {
                        libc::_exit(127);
                    }
                    Ok(())
                });
            }
            Ok(())
        }
    }

    pub(super) fn open_pidfd(process_id: u32) -> io::Result<OwnedFd> {
        let raw_fd = unsafe { libc::syscall(libc::SYS_pidfd_open, process_id, 0) };
        if raw_fd == -1 {
            return Err(io::Error::last_os_error());
        }
        Ok(unsafe { OwnedFd::from_raw_fd(raw_fd as libc::c_int) })
    }

    pub(super) fn signal_pidfd(pidfd: &OwnedFd, signal: libc::c_int) {
        let _ = unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                pidfd.as_raw_fd(),
                signal,
                ptr::null::<libc::siginfo_t>(),
                0,
            )
        };
    }

    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    fn process_policy_filter() -> Vec<libc::sock_filter> {
        let mut filter = vec![
            statement(BPF_LD_W_ABS, SECCOMP_DATA_ARCH_OFFSET),
            jump(BPF_JMP_JEQ_K, audit_arch(), 1, 0),
            statement(BPF_RET_K, SECCOMP_RET_KILL_PROCESS),
            statement(BPF_LD_W_ABS, SECCOMP_DATA_NR_OFFSET),
        ];
        #[cfg(target_arch = "x86_64")]
        filter.push(statement(BPF_ALU_AND_K, !0x4000_0000));

        let denied = [
            libc::SYS_unshare,
            libc::SYS_setns,
            libc::SYS_setsid,
            libc::SYS_setpgid,
            // Linux clears PR_SET_PDEATHSIG when effective/filesystem IDs
            // change. Deny the complete credential-mutating family so a
            // privileged launch cannot discard the host-death binding by
            // dropping or reshaping credentials after exec.
            libc::SYS_setuid,
            libc::SYS_setgid,
            libc::SYS_setreuid,
            libc::SYS_setregid,
            libc::SYS_setresuid,
            libc::SYS_setresgid,
            libc::SYS_setfsuid,
            libc::SYS_setfsgid,
            libc::SYS_setgroups,
        ];
        for syscall in denied {
            filter.push(jump(BPF_JMP_JEQ_K, syscall as u32, 0, 1));
            filter.push(statement(BPF_RET_K, SECCOMP_RET_ERRNO | libc::EPERM as u32));
        }
        #[cfg(target_arch = "x86_64")]
        for syscall in [libc::SYS_fork, libc::SYS_vfork] {
            filter.push(jump(BPF_JMP_JEQ_K, syscall as u32, 0, 1));
            filter.push(statement(BPF_RET_K, SECCOMP_RET_ERRNO | libc::EPERM as u32));
        }

        // Modern runtimes probe clone3() for thread creation and fall back to
        // clone() only on ENOSYS. Deny clone3 entirely because classic seccomp
        // cannot inspect the pointed-to clone_args structure safely.
        filter.push(jump(BPF_JMP_JEQ_K, libc::SYS_clone3 as u32, 0, 1));
        filter.push(statement(
            BPF_RET_K,
            SECCOMP_RET_ERRNO | libc::ENOSYS as u32,
        ));

        // The server may use prctl for harmless runtime metadata, but it may
        // not clear the parent-death signal that ties it to Oxidra.
        filter.push(jump(BPF_JMP_JEQ_K, libc::SYS_prctl as u32, 0, 4));
        filter.push(statement(BPF_LD_W_ABS, SECCOMP_DATA_ARG0_OFFSET));
        filter.push(jump(BPF_JMP_JEQ_K, libc::PR_SET_PDEATHSIG as u32, 0, 1));
        filter.push(statement(BPF_RET_K, SECCOMP_RET_ERRNO | libc::EPERM as u32));
        filter.push(statement(BPF_RET_K, SECCOMP_RET_ALLOW));

        // clone() is allowed only for threads in the same thread group. A
        // separate process, namespace or daemon cannot be created.
        filter.push(jump(BPF_JMP_JEQ_K, libc::SYS_clone as u32, 0, 3));
        filter.push(statement(BPF_LD_W_ABS, SECCOMP_DATA_ARG0_OFFSET));
        filter.push(jump(BPF_JMP_JSET_K, libc::CLONE_THREAD as u32, 1, 0));
        filter.push(statement(BPF_RET_K, SECCOMP_RET_ERRNO | libc::EPERM as u32));
        filter.push(statement(BPF_RET_K, SECCOMP_RET_ALLOW));
        filter
    }

    #[cfg(target_arch = "x86_64")]
    const fn audit_arch() -> u32 {
        0xc000_003e
    }

    #[cfg(target_arch = "aarch64")]
    const fn audit_arch() -> u32 {
        0xc000_00b7
    }

    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    const fn statement(code: u16, value: u32) -> libc::sock_filter {
        libc::sock_filter {
            code,
            jt: 0,
            jf: 0,
            k: value,
        }
    }

    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    const fn jump(code: u16, value: u32, on_true: u8, on_false: u8) -> libc::sock_filter {
        libc::sock_filter {
            code,
            jt: on_true,
            jf: on_false,
            k: value,
        }
    }

    #[cfg(test)]
    mod tests {
        use sha2::{Digest, Sha256};

        use super::process_policy_filter;

        #[test]
        fn linux_mcp_seccomp_policy_v1_is_frozen() {
            let mut bytes = Vec::new();
            for instruction in process_policy_filter() {
                bytes.extend_from_slice(&instruction.code.to_le_bytes());
                bytes.push(instruction.jt);
                bytes.push(instruction.jf);
                bytes.extend_from_slice(&instruction.k.to_le_bytes());
            }
            let digest = hex::encode(Sha256::digest(bytes));
            #[cfg(target_arch = "x86_64")]
            assert_eq!(
                digest,
                "bdde0e838640e64c2608b7aa961d2ac9e3bc76bd05b89b75247d83aa428d2eb4"
            );
            #[cfg(target_arch = "aarch64")]
            assert_eq!(
                digest,
                "7c87ec0a3efcf2fbafa78f4555a12fbc5230a791a47dd478aab6f03716cff9d7"
            );
        }
    }
}
#[cfg(unix)]
impl Drop for ProcessTree {
    fn drop(&mut self) {
        self.terminate_descendants();
    }
}

#[cfg(windows)]
impl Drop for ProcessTree {
    fn drop(&mut self) {
        // A guardian intentionally retains another Job handle across host
        // death, so merely closing this host-side handle would not trigger
        // KILL_ON_JOB_CLOSE.  Ensure panic/unwind paths before the native
        // owner thread is installed still request termination explicitly.
        self.terminate_descendants();
    }
}

#[cfg(windows)]
struct WindowsJob {
    handle: std::os::windows::io::OwnedHandle,
}

#[cfg(windows)]
impl WindowsJob {
    fn attach(child: &Child) -> io::Result<Self> {
        use std::ffi::c_void;
        use std::mem::{size_of, zeroed};
        use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
        use std::ptr;
        use windows_sys::Win32::System::JobObjects::{
            AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
            JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
            SetInformationJobObject,
        };

        let raw_job = unsafe { CreateJobObjectW(ptr::null(), ptr::null()) };
        if raw_job.is_null() {
            return Err(io::Error::last_os_error());
        }
        let handle = unsafe { OwnedHandle::from_raw_handle(raw_job.cast()) };
        let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { zeroed() };
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        let configured = unsafe {
            SetInformationJobObject(
                handle.as_raw_handle().cast(),
                JobObjectExtendedLimitInformation,
                (&raw const limits).cast::<c_void>(),
                size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
        };
        if configured == 0 {
            return Err(io::Error::last_os_error());
        }
        let process = child.raw_handle().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                "child exited before assignment to the Windows Job Object",
            )
        })?;
        let assigned =
            unsafe { AssignProcessToJobObject(handle.as_raw_handle().cast(), process.cast()) };
        if assigned == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self { handle })
    }

    fn terminate(&self) {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::System::JobObjects::TerminateJobObject;

        let _ = unsafe { TerminateJobObject(self.handle.as_raw_handle().cast(), 1) };
    }

    fn wait_empty_blocking(&self) {
        use std::mem::{size_of, zeroed};
        use std::os::windows::io::AsRawHandle;
        use std::ptr;
        use windows_sys::Win32::System::JobObjects::{
            JOBOBJECT_BASIC_ACCOUNTING_INFORMATION, JobObjectBasicAccountingInformation,
            QueryInformationJobObject,
        };

        // A Job Object is not generally documented to become signalled merely
        // because TerminateJobObject made it empty. Query the kernel-owned
        // active-process count instead. Do not turn an unexpected query
        // failure into permission to
        // release the session execution lease. Retrying forever is the
        // deliberate fail-closed outcome: a new journal generation must not
        // start while the old Job cannot be proven empty.
        loop {
            let mut accounting: JOBOBJECT_BASIC_ACCOUNTING_INFORMATION = unsafe { zeroed() };
            let queried = unsafe {
                QueryInformationJobObject(
                    self.handle.as_raw_handle().cast(),
                    JobObjectBasicAccountingInformation,
                    (&raw mut accounting).cast(),
                    size_of::<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION>() as u32,
                    ptr::null_mut(),
                )
            };
            if queried != 0 && accounting.ActiveProcesses == 0 {
                return;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}
