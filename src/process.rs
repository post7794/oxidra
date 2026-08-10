//! Cross-platform ownership and termination of spawned process trees.

use std::io;
use std::time::Duration;

use tokio::process::{Child, Command};

const PROCESS_EXIT_GRACE: Duration = Duration::from_secs(2);

pub(crate) struct ProcessTree {
    process_id: Option<u32>,
    #[cfg(target_os = "linux")]
    linux_contained: bool,
    #[cfg(target_os = "linux")]
    linux_pidfd: Option<std::os::fd::OwnedFd>,
    #[cfg(windows)]
    job: WindowsJob,
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
    pub(crate) fn configure_suspended(command: &mut Command) -> io::Result<()> {
        Self::configure(command);
        #[cfg(target_os = "linux")]
        linux_containment::prepare(command)?;
        #[cfg(all(unix, not(target_os = "linux")))]
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "MCP descendant containment is not implemented for this Unix platform",
        ));
        #[cfg(windows)]
        {
            use windows_sys::Win32::System::Threading::CREATE_SUSPENDED;
            command.creation_flags(CREATE_SUSPENDED);
        }
        Ok(())
    }

    /// Attach ownership immediately after spawn, before any protocol traffic is
    /// sent. Ordinary Unix children use a process group; Linux MCP children use
    /// the stronger pre-exec policy plus a pidfd, and Windows uses a Job Object.
    pub(crate) fn attach(child: &Child) -> io::Result<Self> {
        Self::attach_with_containment(child, false)
    }

    /// Attach the stronger ownership mode required by long-lived MCP servers.
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
    pub(crate) fn resume_suspended(&self) -> io::Result<()> {
        #[cfg(windows)]
        {
            let process_id = self.process_id.ok_or_else(|| {
                io::Error::new(io::ErrorKind::NotFound, "suspended child has no process id")
            })?;
            resume_process_threads(process_id)
        }
        #[cfg(not(windows))]
        Ok(())
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
#[cfg(windows)]
fn resume_process_threads(process_id: u32) -> io::Result<()> {
    use std::mem::{size_of, zeroed};
    use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
    use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, TH32CS_SNAPTHREAD, THREADENTRY32, Thread32First, Thread32Next,
    };
    use windows_sys::Win32::System::Threading::{OpenThread, ResumeThread, THREAD_SUSPEND_RESUME};

    let raw_snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) };
    if raw_snapshot == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    let snapshot = unsafe { OwnedHandle::from_raw_handle(raw_snapshot.cast()) };
    let mut entry: THREADENTRY32 = unsafe { zeroed() };
    entry.dwSize = size_of::<THREADENTRY32>() as u32;
    if unsafe { Thread32First(snapshot.as_raw_handle().cast(), &mut entry) } == 0 {
        return Err(io::Error::last_os_error());
    }

    let mut resumed = 0usize;
    loop {
        if entry.th32OwnerProcessID == process_id {
            let raw_thread = unsafe { OpenThread(THREAD_SUSPEND_RESUME, 0, entry.th32ThreadID) };
            if raw_thread.is_null() {
                return Err(io::Error::last_os_error());
            }
            let thread = unsafe { OwnedHandle::from_raw_handle(raw_thread.cast()) };
            let previous_suspend_count = unsafe { ResumeThread(thread.as_raw_handle().cast()) };
            if previous_suspend_count == u32::MAX {
                return Err(io::Error::last_os_error());
            }
            if previous_suspend_count != 1 {
                return Err(io::Error::other(format!(
                    "MCP child thread had unexpected suspend count {previous_suspend_count}"
                )));
            }
            resumed += 1;
        }
        if unsafe { Thread32Next(snapshot.as_raw_handle().cast(), &mut entry) } == 0 {
            break;
        }
    }
    if resumed == 0 {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "suspended child has no resumable thread",
        ));
    }
    Ok(())
}

#[cfg(unix)]
impl Drop for ProcessTree {
    fn drop(&mut self) {
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
}
