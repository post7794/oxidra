//! Cross-platform ownership and termination of spawned process trees.

use std::io;
use std::time::Duration;

use tokio::process::{Child, Command};

const PROCESS_EXIT_GRACE: Duration = Duration::from_secs(2);

pub(crate) struct ProcessTree {
    process_id: Option<u32>,
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

    /// Attach ownership immediately after spawn, before any protocol traffic is
    /// sent. On Windows the Job Object owns all descendants; on Unix the child
    /// is the leader of the process group configured above.
    pub(crate) fn attach(child: &Child) -> io::Result<Self> {
        let process_id = child.id().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                "child exited before process-tree ownership was established",
            )
        })?;
        #[cfg(windows)]
        let job = WindowsJob::attach(child)?;
        Ok(Self {
            process_id: Some(process_id),
            #[cfg(windows)]
            job,
        })
    }

    /// Kill the complete group/job even when its leader has already exited.
    pub(crate) fn terminate_descendants(&mut self) {
        let process_id = self.process_id.take();
        #[cfg(unix)]
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
