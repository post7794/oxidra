//! Cross-platform ownership and termination of spawned process trees.

use std::io;
use std::time::Duration;

use tokio::process::{Child, Command};

const PROCESS_EXIT_GRACE: Duration = Duration::from_secs(2);

pub(crate) struct ProcessTree {
    process_id: Option<u32>,
    #[cfg(target_os = "linux")]
    linux_root_start_time: Option<u64>,
    #[cfg(target_os = "linux")]
    linux_contained: bool,
    #[cfg(target_os = "linux")]
    linux_registered_root: Option<(i32, u64)>,
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
    /// establishes Oxidra as a child subreaper before spawn and later combines
    /// process-group termination with `/proc` descendant sweeping. Other Unix
    /// targets fail closed until they have an equivalent descendant owner;
    /// a process group alone is not a containment boundary because `setsid()`
    /// can escape it.
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
    /// sent. On Windows the Job Object owns all descendants; on Unix the child
    /// is the leader of the process group configured above.
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
        let linux_root_start_time = match linux_containment::process_start_time(process_id as i32) {
            Ok(start_time) => {
                linux_containment::register_root(process_id as i32, start_time);
                Some(start_time)
            }
            Err(error) if !contained => {
                let _ = error;
                None
            }
            Err(error) => return Err(error),
        };
        #[cfg(not(target_os = "linux"))]
        let _ = contained;
        #[cfg(windows)]
        let job = WindowsJob::attach(child)?;
        Ok(Self {
            process_id: Some(process_id),
            #[cfg(target_os = "linux")]
            linux_root_start_time,
            #[cfg(target_os = "linux")]
            linux_contained: contained,
            #[cfg(target_os = "linux")]
            linux_registered_root: linux_root_start_time
                .map(|start_time| (process_id as i32, start_time)),
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
                if let Some(start_time) = self.linux_root_start_time {
                    linux_containment::terminate(process_id as i32, start_time);
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
    use std::collections::{BTreeMap, BTreeSet};
    use std::fs;
    use std::io;
    use std::os::unix::process::CommandExt;
    use std::sync::{Mutex, OnceLock};
    use std::time::Duration;

    use nix::libc;
    use nix::sys::signal::{Signal, kill, killpg};
    use nix::unistd::{Pid, getpid};
    use tokio::process::Command;

    const SWEEP_PASSES: usize = 8;
    const SWEEP_PAUSE: Duration = Duration::from_millis(5);

    #[derive(Clone, Copy)]
    struct ProcessEntry {
        parent: i32,
        start_time: u64,
    }

    static SUBREAPER_RESULT: OnceLock<std::result::Result<(), i32>> = OnceLock::new();
    static ACTIVE_ROOTS: OnceLock<Mutex<BTreeMap<i32, u64>>> = OnceLock::new();

    pub(super) fn prepare(command: &mut Command) -> io::Result<()> {
        ensure_subreaper()?;
        let processes = scan_processes()?;
        if !processes.contains_key(&getpid().as_raw()) {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "Linux /proc does not expose the current process",
            ));
        }
        // If Oxidra itself exits, at least the direct MCP leader receives a
        // fatal signal. Descendants are cleaned during controlled shutdown by
        // the subreaper + descendant sweep below.
        let owner = getpid().as_raw();
        unsafe {
            command.as_std_mut().pre_exec(move || {
                if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) == -1 {
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

    fn ensure_subreaper() -> io::Result<()> {
        match *SUBREAPER_RESULT.get_or_init(|| {
            let result = unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1) };
            if result == -1 {
                Err(io::Error::last_os_error()
                    .raw_os_error()
                    .unwrap_or(libc::EINVAL))
            } else {
                Ok(())
            }
        }) {
            Ok(()) => Ok(()),
            Err(code) => Err(io::Error::from_raw_os_error(code)),
        }
    }

    pub(super) fn process_start_time(process_id: i32) -> io::Result<u64> {
        let stat = fs::read_to_string(format!("/proc/{process_id}/stat"))?;
        parse_stat(&stat)
            .map(|entry| entry.start_time)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid Linux process stat"))
    }

    pub(super) fn register_root(process_id: i32, start_time: u64) {
        if let Ok(mut roots) = active_roots().lock() {
            roots.insert(process_id, start_time);
        }
    }

    pub(super) fn unregister_root(process_id: i32, start_time: u64) {
        if let Ok(mut roots) = active_roots().lock() {
            if roots.get(&process_id) == Some(&start_time) {
                roots.remove(&process_id);
            }
        }
    }

    pub(super) fn terminate(root: i32, root_start_time: u64) {
        let mut owned = BTreeSet::from([root]);
        let mut stable_passes = 0usize;
        for _ in 0..SWEEP_PASSES {
            let Ok(processes) = scan_processes() else {
                break;
            };
            if processes
                .get(&root)
                .is_some_and(|entry| entry.start_time == root_start_time)
            {
                let _ = killpg(Pid::from_raw(root), Signal::SIGSTOP);
                let _ = kill(Pid::from_raw(root), Signal::SIGSTOP);
            }
            let descendants = descendants_of(&processes, root);
            let previous_len = owned.len();
            for process_id in descendants {
                if process_id != getpid().as_raw() {
                    let _ = kill(Pid::from_raw(process_id), Signal::SIGSTOP);
                    owned.insert(process_id);
                }
            }
            if owned.len() == previous_len {
                stable_passes += 1;
                if stable_passes >= 2 {
                    break;
                }
            } else {
                stable_passes = 0;
            }
            std::thread::sleep(SWEEP_PAUSE);
        }

        for process_id in owned.iter().rev() {
            let _ = kill(Pid::from_raw(*process_id), Signal::SIGKILL);
        }
        let _ = killpg(Pid::from_raw(root), Signal::SIGKILL);

        // A setsid() descendant can leave the original process group. Linux
        // reparents it to this subreaper when its intermediate parent exits.
        // Sweep newly adopted children while excluding every still-registered
        // ProcessTree root, then recursively kill their descendants as well.
        for _ in 0..SWEEP_PASSES {
            std::thread::sleep(SWEEP_PAUSE);
            let Ok(processes) = scan_processes() else {
                break;
            };
            let active = active_roots()
                .lock()
                .map(|roots| roots.clone())
                .unwrap_or_default();
            let owner = getpid().as_raw();
            let adopted_roots = processes
                .iter()
                .filter_map(|(process_id, entry)| {
                    (entry.parent == owner
                        && *process_id != root
                        && entry.start_time >= root_start_time
                        && active.get(process_id) != Some(&entry.start_time))
                    .then_some(*process_id)
                })
                .collect::<Vec<_>>();
            if adopted_roots.is_empty() {
                break;
            }
            for adopted in adopted_roots {
                let mut adopted_tree = descendants_of(&processes, adopted);
                adopted_tree.insert(adopted);
                for process_id in &adopted_tree {
                    let _ = kill(Pid::from_raw(*process_id), Signal::SIGSTOP);
                }
                for process_id in adopted_tree.iter().rev() {
                    let _ = kill(Pid::from_raw(*process_id), Signal::SIGKILL);
                }
            }
        }
    }

    fn active_roots() -> &'static Mutex<BTreeMap<i32, u64>> {
        ACTIVE_ROOTS.get_or_init(|| Mutex::new(BTreeMap::new()))
    }

    fn scan_processes() -> io::Result<BTreeMap<i32, ProcessEntry>> {
        let mut processes = BTreeMap::new();
        for directory in fs::read_dir("/proc")? {
            let Ok(directory) = directory else {
                continue;
            };
            let Some(process_id) = directory
                .file_name()
                .to_str()
                .and_then(|name| name.parse::<i32>().ok())
            else {
                continue;
            };
            let Ok(stat) = fs::read_to_string(directory.path().join("stat")) else {
                continue;
            };
            if let Some(entry) = parse_stat(&stat) {
                processes.insert(process_id, entry);
            }
        }
        Ok(processes)
    }

    fn parse_stat(stat: &str) -> Option<ProcessEntry> {
        let fields = stat
            .get(stat.rfind(')')?.saturating_add(1)..)?
            .split_whitespace();
        let fields = fields.collect::<Vec<_>>();
        Some(ProcessEntry {
            parent: fields.get(1)?.parse().ok()?,
            start_time: fields.get(19)?.parse().ok()?,
        })
    }

    fn descendants_of(processes: &BTreeMap<i32, ProcessEntry>, root: i32) -> BTreeSet<i32> {
        let mut descendants = BTreeSet::new();
        loop {
            let before = descendants.len();
            for (process_id, entry) in processes {
                if entry.parent == root || descendants.contains(&entry.parent) {
                    descendants.insert(*process_id);
                }
            }
            if descendants.len() == before {
                return descendants;
            }
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
        #[cfg(target_os = "linux")]
        if let Some((process_id, start_time)) = self.linux_registered_root.take() {
            linux_containment::unregister_root(process_id, start_time);
        }
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
