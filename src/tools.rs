use std::ffi::OsString;
use std::io;
use std::path::{Component, Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant};

use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::process::Command;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::error::{OxidraError, Result};
use crate::memory::{MAX_MEMORY_FILE_BYTES, MemoryStore};
use crate::process::ProcessTree;
use crate::types::{ToolCall, ToolDefinition, ToolResult};

pub const MAX_TOOL_OUTPUT_LINES: usize = 2_000;
pub const MAX_TOOL_OUTPUT_BYTES: usize = 50 * 1_024;
pub const MAX_FILE_BYTES: u64 = 16 * 1024 * 1024;
pub const MAX_ARTIFACT_BYTES: u64 = 16 * 1024 * 1024;
pub const DEFAULT_SHELL_TIMEOUT_SECS: u64 = 120;
pub const MAX_SHELL_TIMEOUT_SECS: u64 = 3_600;

#[derive(Clone, Debug)]
pub struct ToolContext {
    pub cancellation: CancellationToken,
    pub shell_approved: bool,
    pub memory_approved: bool,
}

impl ToolContext {
    pub fn new(cancellation: CancellationToken) -> Self {
        Self {
            cancellation,
            shell_approved: false,
            memory_approved: false,
        }
    }

    pub fn with_shell_approval(mut self, approved: bool) -> Self {
        self.shell_approved = approved;
        self
    }

    pub fn with_memory_approval(mut self, approved: bool) -> Self {
        self.memory_approved = approved;
        self
    }
}

impl Default for ToolContext {
    fn default() -> Self {
        Self::new(CancellationToken::new())
    }
}

#[derive(Clone, Debug)]
pub struct BuiltinTools {
    root: PathBuf,
    artifact_dir: PathBuf,
    memory: MemoryStore,
    full_auto: bool,
    interactive: bool,
}

impl BuiltinTools {
    pub fn new(
        root: impl AsRef<Path>,
        artifact_dir: impl AsRef<Path>,
        memory_dir: impl AsRef<Path>,
        full_auto: bool,
        interactive: bool,
    ) -> Result<Self> {
        let root = std::fs::canonicalize(root.as_ref()).map_err(|error| {
            OxidraError::tool(
                io_error_code(&error),
                format!("failed to resolve project root: {error}"),
            )
        })?;
        if !root.is_dir() {
            return Err(OxidraError::tool(
                "validation_error",
                format!("project root is not a directory: {}", root.display()),
            ));
        }

        std::fs::create_dir_all(artifact_dir.as_ref()).map_err(|error| {
            OxidraError::tool(
                io_error_code(&error),
                format!("failed to create artifact directory: {error}"),
            )
        })?;
        let artifact_dir = std::fs::canonicalize(artifact_dir.as_ref()).map_err(|error| {
            OxidraError::tool(
                io_error_code(&error),
                format!("failed to resolve artifact directory: {error}"),
            )
        })?;
        let memory = MemoryStore::new(memory_dir.as_ref().to_owned())?;

        Ok(Self {
            root,
            artifact_dir,
            memory,
            full_auto,
            interactive,
        })
    }

    pub fn definitions(&self) -> Vec<ToolDefinition> {
        Self::tool_definitions()
    }

    pub async fn execute(&self, call: &ToolCall, context: &ToolContext) -> ToolResult {
        match call.name.as_str() {
            "read" => self.read(call, context).await,
            "edit" => self.edit(call, context).await,
            "write" => self.write(call, context).await,
            "remember" => self.remember(call, context).await,
            "shell" => self.shell(call, context).await,
            _ => ToolResult::error(
                &call.id,
                "validation_error",
                format!("unknown built-in tool: {}", call.name),
            ),
        }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn artifact_dir(&self) -> &Path {
        &self.artifact_dir
    }

    pub fn shell_kind(&self) -> &'static str {
        if cfg!(windows) { "powershell" } else { "sh" }
    }

    async fn read(&self, call: &ToolCall, context: &ToolContext) -> ToolResult {
        let args: ReadArgs = match parse_arguments(call) {
            Ok(args) => args,
            Err(result) => return result,
        };
        if context.cancellation.is_cancelled() {
            return ToolResult::error(&call.id, "cancelled", "read was cancelled");
        }
        if args.limit == Some(0)
            || args
                .limit
                .is_some_and(|limit| limit > MAX_TOOL_OUTPUT_LINES)
        {
            return ToolResult::error(
                &call.id,
                "validation_error",
                format!("limit must be between 1 and {MAX_TOOL_OUTPUT_LINES}"),
            );
        }

        let path = match self.resolve_existing_path(&args.path).await {
            Ok(path) => path,
            Err(error) => return error_result(&call.id, error),
        };
        let metadata = match tokio::fs::metadata(&path).await {
            Ok(metadata) => metadata,
            Err(error) => return io_result(&call.id, "read file metadata", error),
        };
        if metadata.len() > MAX_FILE_BYTES {
            return ToolResult::error(
                &call.id,
                "validation_error",
                format!("file exceeds the {MAX_FILE_BYTES}-byte read limit"),
            );
        }
        let bytes = match tokio::select! {
            _ = context.cancellation.cancelled() => {
                return ToolResult::error(&call.id, "cancelled", "read was cancelled");
            }
            result = tokio::fs::read(&path) => result,
        } {
            Ok(bytes) => bytes,
            Err(error) => return io_result(&call.id, "read file", error),
        };
        if bytes.len() as u64 > MAX_FILE_BYTES {
            return ToolResult::error(
                &call.id,
                "validation_error",
                format!("file grew beyond the {MAX_FILE_BYTES}-byte read limit"),
            );
        }
        let full_file_sha256 = sha256_hex(&bytes);
        let text = match String::from_utf8(bytes) {
            Ok(text) => text,
            Err(_) => {
                return ToolResult::error(
                    &call.id,
                    "validation_error",
                    "read only supports UTF-8 text files",
                );
            }
        };

        if args.byte_offset.is_some() && args.offset.is_some() {
            return ToolResult::error(
                &call.id,
                "validation_error",
                "offset and byte_offset cannot be used together",
            );
        }
        let byte_offset = args.byte_offset.unwrap_or(0);
        if byte_offset > text.len() || !text.is_char_boundary(byte_offset) {
            return ToolResult::error(
                &call.id,
                "validation_error",
                "byte_offset must point to a UTF-8 character boundary",
            );
        }
        let view = &text[byte_offset..];
        let lines = split_lines(view);
        let total_lines = lines.len();
        let offset = args.offset.unwrap_or(0);
        let limit = args.limit.unwrap_or(MAX_TOOL_OUTPUT_LINES);
        let mut output = String::new();
        let mut returned_lines = 0usize;
        let mut partial_line = false;
        let mut next_byte_offset = byte_offset;
        let mut line_byte_offset = byte_offset
            + lines
                .iter()
                .take(offset)
                .map(|line| line.len())
                .sum::<usize>();

        for line in lines.iter().skip(offset).take(limit) {
            let remaining = MAX_TOOL_OUTPUT_BYTES.saturating_sub(output.len());
            if remaining == 0 {
                break;
            }
            if line.len() <= remaining {
                output.push_str(line);
                returned_lines += 1;
                line_byte_offset += line.len();
                next_byte_offset = line_byte_offset;
                continue;
            }

            let boundary = floor_char_boundary(line, remaining);
            if boundary == 0 {
                return ToolResult::error(
                    &call.id,
                    "output_limit",
                    "remaining output budget is smaller than one UTF-8 character",
                );
            }
            output.push_str(&line[..boundary]);
            next_byte_offset = line_byte_offset + boundary;
            partial_line = true;
            break;
        }

        let consumed_lines = offset.saturating_add(returned_lines).min(total_lines);
        let truncated = partial_line
            || offset < total_lines && consumed_lines < total_lines
            || offset > total_lines;
        ToolResult::success(
            &call.id,
            json!({
                "text": output,
                "full_file_sha256": full_file_sha256,
                "range": {
                    "offset": offset,
                    "returned_lines": returned_lines,
                    "start_line": if returned_lines == 0 { Value::Null } else { json!(offset + 1) },
                    "end_line": if returned_lines == 0 { Value::Null } else { json!(consumed_lines) },
                    "total_lines": total_lines,
                    "byte_offset": byte_offset,
                    "next_byte_offset": next_byte_offset,
                },
                "truncated": truncated,
            }),
        )
    }

    async fn edit(&self, call: &ToolCall, context: &ToolContext) -> ToolResult {
        let args: EditArgs = match parse_arguments(call) {
            Ok(args) => args,
            Err(result) => return result,
        };
        if context.cancellation.is_cancelled() {
            return ToolResult::error(&call.id, "cancelled", "edit was cancelled");
        }
        if args.old_text.is_empty() {
            return ToolResult::error(&call.id, "validation_error", "old_text must not be empty");
        }
        if !is_sha256(&args.expected_sha256) {
            return ToolResult::error(
                &call.id,
                "validation_error",
                "expected_sha256 must be 64 hexadecimal characters",
            );
        }

        let path = match self.resolve_existing_path(&args.path).await {
            Ok(path) => path,
            Err(error) => return error_result(&call.id, error),
        };
        let metadata = match tokio::fs::metadata(&path).await {
            Ok(metadata) => metadata,
            Err(error) => return io_result(&call.id, "read file metadata", error),
        };
        if metadata.len() > MAX_FILE_BYTES {
            return ToolResult::error(
                &call.id,
                "validation_error",
                format!("file exceeds the {MAX_FILE_BYTES}-byte edit limit"),
            );
        }
        let original = match tokio::select! {
            _ = context.cancellation.cancelled() => {
                return ToolResult::error(&call.id, "cancelled", "edit was cancelled");
            }
            result = tokio::fs::read(&path) => result,
        } {
            Ok(bytes) => bytes,
            Err(error) => return io_result(&call.id, "read file before edit", error),
        };
        if original.len() as u64 > MAX_FILE_BYTES {
            return ToolResult::error(
                &call.id,
                "validation_error",
                format!("file grew beyond the {MAX_FILE_BYTES}-byte edit limit"),
            );
        }
        let original_hash = sha256_hex(&original);
        if !original_hash.eq_ignore_ascii_case(&args.expected_sha256) {
            return ToolResult::error(
                &call.id,
                "stale_file",
                format!(
                    "file changed since it was read (expected {}, found {original_hash})",
                    args.expected_sha256
                ),
            );
        }
        let original_text = match String::from_utf8(original) {
            Ok(text) => text,
            Err(_) => {
                return ToolResult::error(
                    &call.id,
                    "validation_error",
                    "edit only supports UTF-8 text files",
                );
            }
        };

        let matches = original_text.match_indices(&args.old_text).take(2).count();
        if matches != 1 {
            return ToolResult::error(
                &call.id,
                "validation_error",
                format!("old_text must match exactly once; found {matches} matches"),
            );
        }
        let replacement = original_text.replacen(&args.old_text, &args.new_text, 1);
        let new_hash = sha256_hex(replacement.as_bytes());
        if !metadata.is_file() {
            return ToolResult::error(
                &call.id,
                "validation_error",
                "edit target is not a regular file",
            );
        }

        let temp_path = temporary_sibling(&path);
        let mut temp = match tokio::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp_path)
            .await
        {
            Ok(file) => file,
            Err(error) => return io_result(&call.id, "create temporary edit file", error),
        };
        if let Err(error) = temp.write_all(replacement.as_bytes()).await {
            drop(temp);
            let _ = tokio::fs::remove_file(&temp_path).await;
            return io_result(&call.id, "write temporary edit file", error);
        }
        if let Err(error) = temp.sync_all().await {
            drop(temp);
            let _ = tokio::fs::remove_file(&temp_path).await;
            return io_result(&call.id, "flush temporary edit file", error);
        }
        drop(temp);
        if let Err(error) = tokio::fs::set_permissions(&temp_path, metadata.permissions()).await {
            let _ = tokio::fs::remove_file(&temp_path).await;
            return io_result(&call.id, "preserve file permissions", error);
        }

        if context.cancellation.is_cancelled() {
            let _ = tokio::fs::remove_file(&temp_path).await;
            return ToolResult::error(&call.id, "cancelled", "edit was cancelled");
        }

        // Recheck immediately before replacement to narrow the optimistic-lock race.
        let current = match tokio::select! {
            _ = context.cancellation.cancelled() => {
                let _ = tokio::fs::remove_file(&temp_path).await;
                return ToolResult::error(&call.id, "cancelled", "edit was cancelled");
            }
            result = tokio::fs::read(&path) => result,
        } {
            Ok(bytes) => bytes,
            Err(error) => {
                let _ = tokio::fs::remove_file(&temp_path).await;
                return io_result(&call.id, "recheck file before edit", error);
            }
        };
        if current.len() as u64 > MAX_FILE_BYTES {
            let _ = tokio::fs::remove_file(&temp_path).await;
            return ToolResult::error(
                &call.id,
                "validation_error",
                format!("file grew beyond the {MAX_FILE_BYTES}-byte edit limit"),
            );
        }
        let current_hash = sha256_hex(&current);
        if current_hash != original_hash {
            let _ = tokio::fs::remove_file(&temp_path).await;
            return ToolResult::error(
                &call.id,
                "stale_file",
                format!("file changed while edit was prepared (found {current_hash})"),
            );
        }

        if context.cancellation.is_cancelled() {
            let _ = tokio::fs::remove_file(&temp_path).await;
            return ToolResult::error(&call.id, "cancelled", "edit was cancelled");
        }

        if let Err(error) = atomic_replace(&temp_path, &path).await {
            let _ = tokio::fs::remove_file(&temp_path).await;
            return io_result(&call.id, "atomically replace edited file", error);
        }

        ToolResult::success(
            &call.id,
            json!({
                "replaced_count": 1,
                "new_sha256": new_hash,
            }),
        )
    }

    async fn write(&self, call: &ToolCall, context: &ToolContext) -> ToolResult {
        let args: WriteArgs = match parse_arguments(call) {
            Ok(args) => args,
            Err(result) => return result,
        };
        if context.cancellation.is_cancelled() {
            return ToolResult::error(&call.id, "cancelled", "write was cancelled");
        }
        if args.content.len() as u64 > MAX_FILE_BYTES {
            return ToolResult::error(
                &call.id,
                "validation_error",
                format!("content exceeds the {MAX_FILE_BYTES}-byte write limit"),
            );
        }

        let path = match self.resolve_new_path(&args.path).await {
            Ok(path) => path,
            Err(error) => return error_result(&call.id, error),
        };
        let temp_path = temporary_sibling(&path);
        let mut temp = match tokio::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp_path)
            .await
        {
            Ok(file) => file,
            Err(error) => return io_result(&call.id, "create temporary write file", error),
        };
        if let Err(error) = temp.write_all(args.content.as_bytes()).await {
            drop(temp);
            let _ = tokio::fs::remove_file(&temp_path).await;
            return io_result(&call.id, "write temporary file", error);
        }
        if let Err(error) = temp.sync_all().await {
            drop(temp);
            let _ = tokio::fs::remove_file(&temp_path).await;
            return io_result(&call.id, "flush temporary write file", error);
        }
        drop(temp);

        if context.cancellation.is_cancelled() {
            let _ = tokio::fs::remove_file(&temp_path).await;
            return ToolResult::error(&call.id, "cancelled", "write was cancelled");
        }

        // A hard link publishes the fully-written sibling atomically and, unlike
        // rename on Unix, never replaces a destination created by a racing actor.
        if let Err(error) = tokio::fs::hard_link(&temp_path, &path).await {
            let _ = tokio::fs::remove_file(&temp_path).await;
            let operation = if error.kind() == io::ErrorKind::AlreadyExists {
                "create file without overwriting existing target"
            } else {
                "atomically publish new file"
            };
            return io_result(&call.id, operation, error);
        }
        let _ = tokio::fs::remove_file(&temp_path).await;

        ToolResult::success(
            &call.id,
            json!({
                "path": args.path,
                "bytes": args.content.len(),
                "sha256": sha256_hex(args.content.as_bytes()),
            }),
        )
    }

    async fn remember(&self, call: &ToolCall, context: &ToolContext) -> ToolResult {
        let args: RememberArgs = match parse_arguments(call) {
            Ok(args) => args,
            Err(result) => return result,
        };
        if context.cancellation.is_cancelled() {
            return ToolResult::error(&call.id, "cancelled", "remember was cancelled");
        }
        if !context.memory_approved {
            return ToolResult::error(
                &call.id,
                "approval_required",
                "remember requires user confirmation",
            );
        }
        match self.memory.remember(&args.content, &self.root) {
            Ok(entry) => ToolResult::success(
                &call.id,
                json!({
                    "id": entry.id,
                    "bytes": entry.bytes,
                }),
            ),
            Err(error) => error_result(&call.id, error),
        }
    }

    async fn shell(&self, call: &ToolCall, context: &ToolContext) -> ToolResult {
        let args: ShellArgs = match parse_arguments(call) {
            Ok(args) => args,
            Err(result) => return result,
        };
        if args.command.trim().is_empty() {
            return ToolResult::error(&call.id, "validation_error", "command must not be empty");
        }
        let timeout_secs = args.timeout.unwrap_or(DEFAULT_SHELL_TIMEOUT_SECS);
        if timeout_secs == 0 || timeout_secs > MAX_SHELL_TIMEOUT_SECS {
            return ToolResult::error(
                &call.id,
                "validation_error",
                format!("timeout must be between 1 and {MAX_SHELL_TIMEOUT_SECS} seconds"),
            );
        }
        if !self.full_auto && !context.shell_approved {
            let message = if self.interactive {
                "shell command requires user confirmation"
            } else {
                "shell command requires --full-auto in non-interactive mode"
            };
            return ToolResult::error(&call.id, "approval_required", message);
        }
        if context.cancellation.is_cancelled() {
            return ToolResult::error(&call.id, "cancelled", "shell command was cancelled");
        }

        match self
            .run_shell(&args.command, timeout_secs, &context.cancellation)
            .await
        {
            Ok(execution) => execution.into_tool_result(&call.id),
            Err(error) => error_result(&call.id, error),
        }
    }

    async fn resolve_existing_path(&self, requested: &str) -> Result<PathBuf> {
        if requested.trim().is_empty() {
            return Err(OxidraError::tool(
                "validation_error",
                "path must not be empty",
            ));
        }
        let requested = Path::new(requested);
        if requested
            .components()
            .any(|component| matches!(component, Component::ParentDir))
        {
            return Err(OxidraError::tool(
                "permission_denied",
                "path must not contain '..' components",
            ));
        }
        let candidate = if requested.is_absolute() {
            requested.to_path_buf()
        } else {
            self.root.join(requested)
        };
        let canonical = tokio::fs::canonicalize(&candidate).await.map_err(|error| {
            OxidraError::tool(
                io_error_code(&error),
                format!("failed to resolve {}: {error}", candidate.display()),
            )
        })?;
        if !path_is_within(&self.root, &canonical) {
            return Err(OxidraError::tool(
                "permission_denied",
                format!(
                    "path escapes project root: {} is outside {}",
                    canonical.display(),
                    self.root.display()
                ),
            ));
        }
        Ok(canonical)
    }

    async fn resolve_new_path(&self, requested: &str) -> Result<PathBuf> {
        if requested.trim().is_empty() {
            return Err(OxidraError::tool(
                "validation_error",
                "path must not be empty",
            ));
        }
        let requested = Path::new(requested);
        if requested.is_absolute() {
            return Err(OxidraError::tool(
                "permission_denied",
                "write path must be relative to the project root",
            ));
        }
        if requested.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        }) {
            return Err(OxidraError::tool(
                "permission_denied",
                "write path must not contain '..', root, or prefix components",
            ));
        }
        let file_name = requested
            .file_name()
            .ok_or_else(|| OxidraError::tool("validation_error", "write path must name a file"))?;
        let parent = requested.parent().unwrap_or_else(|| Path::new(""));
        let parent = tokio::fs::canonicalize(self.root.join(parent))
            .await
            .map_err(|error| {
                OxidraError::tool(
                    io_error_code(&error),
                    format!("failed to resolve write parent directory: {error}"),
                )
            })?;
        if !path_is_within(&self.root, &parent) {
            return Err(OxidraError::tool(
                "permission_denied",
                format!("write parent escapes project root: {}", parent.display()),
            ));
        }
        if !tokio::fs::metadata(&parent).await?.is_dir() {
            return Err(OxidraError::tool(
                "validation_error",
                "write parent is not a directory",
            ));
        }
        let destination = parent.join(file_name);
        match tokio::fs::symlink_metadata(&destination).await {
            Ok(_) => Err(OxidraError::tool(
                "already_exists",
                format!(
                    "write refuses to overwrite existing path: {}",
                    destination.display()
                ),
            )),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(destination),
            Err(error) => Err(error.into()),
        }
    }

    async fn run_shell(
        &self,
        command_text: &str,
        timeout_secs: u64,
        cancellation: &CancellationToken,
    ) -> Result<ShellExecution> {
        tokio::fs::create_dir_all(&self.artifact_dir).await?;
        let invocation_id = Uuid::now_v7().to_string();
        let stdout_spool = self
            .artifact_dir
            .join(format!(".{invocation_id}.stdout.tmp"));
        let stderr_spool = self
            .artifact_dir
            .join(format!(".{invocation_id}.stderr.tmp"));

        let mut command = platform_shell_command(command_text);
        command
            .current_dir(&self.root)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        ProcessTree::configure(&mut command);
        let started = Instant::now();
        let mut child = command.spawn().map_err(|error| {
            OxidraError::tool(
                io_error_code(&error),
                format!("failed to start {} shell: {error}", self.shell_kind()),
            )
        })?;
        let mut process_tree = match ProcessTree::attach(&child) {
            Ok(process_tree) => process_tree,
            Err(error) => {
                let _ = child.start_kill();
                let _ = tokio::time::timeout(Duration::from_secs(2), child.wait()).await;
                return Err(OxidraError::tool(
                    "process_exit",
                    format!("failed to take ownership of shell process tree: {error}"),
                ));
            }
        };
        let stdout = match child.stdout.take() {
            Some(stdout) => stdout,
            None => {
                process_tree.terminate(&mut child).await;
                return Err(OxidraError::tool(
                    "process_exit",
                    "shell stdout was not captured",
                ));
            }
        };
        let stderr = match child.stderr.take() {
            Some(stderr) => stderr,
            None => {
                process_tree.terminate(&mut child).await;
                return Err(OxidraError::tool(
                    "process_exit",
                    "shell stderr was not captured",
                ));
            }
        };
        let stdout_task = tokio::spawn(capture_stream(stdout, stdout_spool.clone()));
        let stderr_task = tokio::spawn(capture_stream(stderr, stderr_spool.clone()));

        let completion = tokio::select! {
            biased;
            _ = cancellation.cancelled() => {
                process_tree.terminate(&mut child).await;
                ShellCompletion::Cancelled
            }
            _ = tokio::time::sleep(Duration::from_secs(timeout_secs)) => {
                process_tree.terminate(&mut child).await;
                ShellCompletion::TimedOut
            }
            status = child.wait() => {
                match status {
                    Ok(status) => ShellCompletion::Exited(status.code()),
                    Err(error) => {
                        process_tree.terminate(&mut child).await;
                        ShellCompletion::WaitFailed(error.to_string())
                    }
                }
            }
        };
        // A shell may let its leader exit while background descendants retain
        // stdout/stderr. Always close the owned group before draining pipes.
        process_tree.terminate_descendants();

        let (stdout_result, stderr_result) = tokio::join!(
            join_capture_bounded(stdout_task, &stdout_spool),
            join_capture_bounded(stderr_task, &stderr_spool),
        );
        let stdout = stdout_result?;
        let stderr = stderr_result?;
        let (stdout_limit, stderr_limit) = fair_allocations(
            MAX_TOOL_OUTPUT_BYTES,
            stdout.prefix.len(),
            stderr.prefix.len(),
        );
        let (stdout_line_limit, stderr_line_limit) = fair_allocations(
            MAX_TOOL_OUTPUT_LINES,
            count_lines(&stdout.prefix),
            count_lines(&stderr.prefix),
        );
        let stdout_returned = bounded_prefix(&stdout.prefix, stdout_limit, stdout_line_limit);
        let stderr_returned = bounded_prefix(&stderr.prefix, stderr_limit, stderr_line_limit);
        let truncated = stdout.total_bytes > stdout_returned.len() as u64
            || stderr.total_bytes > stderr_returned.len() as u64;

        let artifact = if truncated {
            Some(
                self.commit_shell_artifact(
                    &invocation_id,
                    command_text,
                    &completion,
                    &stdout,
                    &stderr,
                )
                .await?,
            )
        } else {
            let _ = tokio::fs::remove_file(&stdout.spool_path).await;
            let _ = tokio::fs::remove_file(&stderr.spool_path).await;
            None
        };

        Ok(ShellExecution {
            completion,
            stdout: String::from_utf8_lossy(stdout_returned).into_owned(),
            stderr: String::from_utf8_lossy(stderr_returned).into_owned(),
            stdout_sha256: stdout.sha256,
            stderr_sha256: stderr.sha256,
            truncated,
            artifact,
            duration_ms: started.elapsed().as_millis() as u64,
        })
    }

    async fn commit_shell_artifact(
        &self,
        id: &str,
        command: &str,
        completion: &ShellCompletion,
        stdout: &StreamCapture,
        stderr: &StreamCapture,
    ) -> Result<ArtifactReference> {
        let directory = self.artifact_dir.join(id);
        tokio::fs::create_dir(&directory).await?;
        let stdout_path = directory.join("stdout.bin");
        let stderr_path = directory.join("stderr.bin");
        tokio::fs::rename(&stdout.spool_path, &stdout_path).await?;
        if let Err(error) = tokio::fs::rename(&stderr.spool_path, &stderr_path).await {
            let _ = tokio::fs::rename(&stdout_path, &stdout.spool_path).await;
            let _ = tokio::fs::remove_dir(&directory).await;
            return Err(error.into());
        }

        let metadata = json!({
            "schema": 1,
            "kind": "shell_output",
            "command": command,
            "completion": completion.label(),
            "exit_code": completion.exit_code(),
            "stdout": {
                "file": "stdout.bin",
                "bytes": stdout.total_bytes,
                "stored_bytes": stdout.stored_bytes,
                "artifact_truncated": stdout.artifact_truncated,
                "sha256": stdout.sha256,
            },
            "stderr": {
                "file": "stderr.bin",
                "bytes": stderr.total_bytes,
                "stored_bytes": stderr.stored_bytes,
                "artifact_truncated": stderr.artifact_truncated,
                "sha256": stderr.sha256,
            },
        });
        let metadata_bytes = serde_json::to_vec_pretty(&metadata)?;
        let metadata_path = directory.join("metadata.json");
        tokio::fs::write(&metadata_path, &metadata_bytes).await?;
        let metadata_file = tokio::fs::File::open(&metadata_path).await?;
        metadata_file.sync_data().await?;
        Ok(ArtifactReference {
            id: id.to_owned(),
            sha256: sha256_hex(&metadata_bytes),
        })
    }

    fn tool_definitions() -> Vec<ToolDefinition> {
        vec![
            ToolDefinition {
                name: "read".to_owned(),
                description: "Read UTF-8 text from a file inside the project root. offset is a zero-based line offset; byte_offset resumes a response split inside a very long line. Each response is capped at 2,000 lines and 50 KiB.".to_owned(),
                input_schema: json!({
                    "type": "object",
                    "additionalProperties": false,
                    "properties": {
                        "path": { "type": "string", "minLength": 1 },
                        "offset": { "type": "integer", "minimum": 0 },
                        "byte_offset": { "type": "integer", "minimum": 0 },
                        "limit": { "type": "integer", "minimum": 1, "maximum": MAX_TOOL_OUTPUT_LINES },
                    },
                    "required": ["path"],
                }),
            },
            ToolDefinition {
                name: "edit".to_owned(),
                description: "Replace exactly one literal UTF-8 text occurrence in a project file, guarded by the full-file SHA-256 returned by read.".to_owned(),
                input_schema: json!({
                    "type": "object",
                    "additionalProperties": false,
                    "properties": {
                        "path": { "type": "string", "minLength": 1 },
                        "old_text": { "type": "string", "minLength": 1 },
                        "new_text": { "type": "string" },
                        "expected_sha256": { "type": "string", "pattern": "^[0-9a-fA-F]{64}$" },
                    },
                    "required": ["path", "old_text", "new_text", "expected_sha256"],
                }),
            },
            ToolDefinition {
                name: "write".to_owned(),
                description: format!(
                    "Create a new UTF-8 file inside the project root without overwriting an existing path. Parent directories must already exist. Content is limited to {MAX_FILE_BYTES} bytes."
                ),
                input_schema: json!({
                    "type": "object",
                    "additionalProperties": false,
                    "properties": {
                        "path": { "type": "string", "minLength": 1 },
                        "content": { "type": "string" },
                    },
                    "required": ["path", "content"],
                }),
            },
            ToolDefinition {
                name: "remember".to_owned(),
                description: format!(
                    "Persist one user-approved memory as a local Markdown file for future Oxidra sessions. The complete file including provenance frontmatter is limited to {MAX_MEMORY_FILE_BYTES} bytes."
                ),
                input_schema: json!({
                    "type": "object",
                    "additionalProperties": false,
                    "properties": {
                        "content": {
                            "type": "string",
                            "minLength": 1,
                            "description": "The exact memory text to persist."
                        },
                    },
                    "required": ["content"],
                }),
            },
            ToolDefinition {
                name: "shell".to_owned(),
                description: format!(
                    "Run a command from the project root using {}. Output is bounded; full truncated output is saved as an artifact.",
                    if cfg!(windows) { "PowerShell" } else { "/bin/sh" }
                ),
                input_schema: json!({
                    "type": "object",
                    "additionalProperties": false,
                    "properties": {
                        "command": { "type": "string", "minLength": 1 },
                        "timeout": {
                            "type": "integer",
                            "minimum": 1,
                            "maximum": MAX_SHELL_TIMEOUT_SECS,
                            "description": "Timeout in seconds; defaults to 120."
                        },
                    },
                    "required": ["command"],
                }),
            },
        ]
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReadArgs {
    path: String,
    offset: Option<usize>,
    byte_offset: Option<usize>,
    limit: Option<usize>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EditArgs {
    path: String,
    old_text: String,
    new_text: String,
    expected_sha256: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WriteArgs {
    path: String,
    content: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RememberArgs {
    content: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ShellArgs {
    command: String,
    timeout: Option<u64>,
}

fn parse_arguments<T: for<'de> Deserialize<'de>>(
    call: &ToolCall,
) -> std::result::Result<T, ToolResult> {
    serde_json::from_value(call.arguments.clone()).map_err(|error| {
        ToolResult::error(
            &call.id,
            "validation_error",
            format!("invalid {} arguments: {error}", call.name),
        )
    })
}

fn split_lines(text: &str) -> Vec<&str> {
    if text.is_empty() {
        Vec::new()
    } else {
        text.split_inclusive('\n').collect()
    }
}

fn floor_char_boundary(text: &str, mut index: usize) -> usize {
    index = index.min(text.len());
    while !text.is_char_boundary(index) {
        index -= 1;
    }
    index
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn path_is_within(root: &Path, candidate: &Path) -> bool {
    let mut root_components = root.components();
    let mut candidate_components = candidate.components();
    loop {
        match (root_components.next(), candidate_components.next()) {
            (None, _) => return true,
            (Some(root), Some(candidate)) if path_component_eq(root, candidate) => {}
            _ => return false,
        }
    }
}

fn path_component_eq(left: Component<'_>, right: Component<'_>) -> bool {
    #[cfg(windows)]
    {
        left.as_os_str()
            .to_string_lossy()
            .eq_ignore_ascii_case(&right.as_os_str().to_string_lossy())
    }
    #[cfg(not(windows))]
    {
        left == right
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn temporary_sibling(path: &Path) -> PathBuf {
    let mut name = OsString::from(".");
    name.push(path.file_name().unwrap_or_default());
    name.push(format!(".oxidra-{}.tmp", Uuid::now_v7()));
    path.with_file_name(name)
}

#[cfg(windows)]
async fn atomic_replace(source: &Path, destination: &Path) -> io::Result<()> {
    use std::os::windows::ffi::OsStrExt;

    const MOVEFILE_REPLACE_EXISTING: u32 = 0x1;
    const MOVEFILE_WRITE_THROUGH: u32 = 0x8;

    #[link(name = "Kernel32")]
    unsafe extern "system" {
        fn MoveFileExW(
            existing_file_name: *const u16,
            new_file_name: *const u16,
            flags: u32,
        ) -> i32;
    }

    let source: Vec<u16> = source.as_os_str().encode_wide().chain(Some(0)).collect();
    let destination: Vec<u16> = destination
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect();
    let result = unsafe {
        MoveFileExW(
            source.as_ptr(),
            destination.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    };
    if result == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(not(windows))]
async fn atomic_replace(source: &Path, destination: &Path) -> io::Result<()> {
    tokio::fs::rename(source, destination).await
}

fn platform_shell_command(command_text: &str) -> Command {
    #[cfg(windows)]
    {
        let mut command =
            Command::new(windows_system32().join("WindowsPowerShell/v1.0/powershell.exe"));
        command.args(["-NoLogo", "-NoProfile", "-NonInteractive", "-Command"]);
        command.arg(command_text);
        command
    }
    #[cfg(not(windows))]
    {
        let mut command = Command::new("/bin/sh");
        command.args(["-lc", command_text]);
        command
    }
}

#[cfg(windows)]
fn windows_system32() -> PathBuf {
    std::env::var_os("SystemRoot")
        .or_else(|| std::env::var_os("WINDIR"))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\Windows"))
        .join("System32")
}

#[derive(Debug)]
struct StreamCapture {
    prefix: Vec<u8>,
    total_bytes: u64,
    sha256: String,
    spool_path: PathBuf,
    stored_bytes: u64,
    artifact_truncated: bool,
}

async fn capture_stream<R>(mut reader: R, spool_path: PathBuf) -> io::Result<StreamCapture>
where
    R: AsyncRead + Unpin,
{
    let mut spool = tokio::fs::File::create(&spool_path).await?;
    let mut prefix = Vec::with_capacity(MAX_TOOL_OUTPUT_BYTES);
    let mut total_bytes = 0u64;
    let mut stored_bytes = 0u64;
    let mut artifact_truncated = false;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 8 * 1_024];
    loop {
        let read = reader.read(&mut buffer).await?;
        if read == 0 {
            break;
        }
        let chunk = &buffer[..read];
        let remaining = MAX_ARTIFACT_BYTES.saturating_sub(stored_bytes);
        if remaining > 0 {
            let stored = (read as u64).min(remaining) as usize;
            spool.write_all(&chunk[..stored]).await?;
            stored_bytes = stored_bytes.saturating_add(stored as u64);
            if stored < read {
                artifact_truncated = true;
            }
        } else {
            artifact_truncated = true;
        }
        hasher.update(chunk);
        total_bytes = total_bytes.saturating_add(read as u64);
        let remaining = MAX_TOOL_OUTPUT_BYTES.saturating_sub(prefix.len());
        prefix.extend_from_slice(&chunk[..read.min(remaining)]);
    }
    spool.flush().await?;
    spool.sync_data().await?;
    Ok(StreamCapture {
        prefix,
        total_bytes,
        sha256: hex::encode(hasher.finalize()),
        spool_path,
        stored_bytes,
        artifact_truncated,
    })
}

async fn join_capture_bounded(
    mut task: JoinHandle<io::Result<StreamCapture>>,
    spool_path: &Path,
) -> Result<StreamCapture> {
    let joined = tokio::time::timeout(Duration::from_secs(2), &mut task).await;
    if joined.is_err() {
        task.abort();
        let _ = tokio::fs::remove_file(spool_path).await;
        return Err(OxidraError::tool(
            "in_doubt",
            "shell output pipes did not close after the process ended; side effects are unknown",
        ));
    }
    match joined.expect("capture timeout result was checked") {
        Ok(Ok(capture)) => Ok(capture),
        Ok(Err(error)) => {
            let _ = tokio::fs::remove_file(spool_path).await;
            Err(error.into())
        }
        Err(error) => {
            let _ = tokio::fs::remove_file(spool_path).await;
            Err(OxidraError::tool(
                "process_exit",
                format!("shell output capture task failed: {error}"),
            ))
        }
    }
}

fn fair_allocations(total: usize, first_need: usize, second_need: usize) -> (usize, usize) {
    let half = total / 2;
    let mut first = first_need.min(half);
    let mut second = second_need.min(total - half);
    let remaining = total.saturating_sub(first + second);
    let first_extra = first_need.saturating_sub(first).min(remaining);
    first += first_extra;
    let remaining = total.saturating_sub(first + second);
    second += second_need.saturating_sub(second).min(remaining);
    (first, second)
}

fn count_lines(bytes: &[u8]) -> usize {
    if bytes.is_empty() {
        0
    } else {
        bytes.iter().filter(|&&byte| byte == b'\n').count()
            + usize::from(bytes.last() != Some(&b'\n'))
    }
}

fn bounded_prefix(bytes: &[u8], byte_limit: usize, line_limit: usize) -> &[u8] {
    let byte_limit = byte_limit.min(bytes.len());
    if byte_limit == 0 || line_limit == 0 {
        return &bytes[..0];
    }
    let mut lines = 0usize;
    let mut at_line_start = true;
    let mut end = 0usize;
    for (index, &byte) in bytes[..byte_limit].iter().enumerate() {
        if at_line_start {
            if lines == line_limit {
                break;
            }
            lines += 1;
            at_line_start = false;
        }
        end = index + 1;
        if byte == b'\n' {
            at_line_start = true;
        }
    }
    &bytes[..end]
}

#[derive(Debug)]
enum ShellCompletion {
    Exited(Option<i32>),
    TimedOut,
    Cancelled,
    WaitFailed(String),
}

impl ShellCompletion {
    fn label(&self) -> &'static str {
        match self {
            Self::Exited(_) => "exited",
            Self::TimedOut => "timeout",
            Self::Cancelled => "cancelled",
            Self::WaitFailed(_) => "wait_failed",
        }
    }

    fn exit_code(&self) -> Option<i32> {
        match self {
            Self::Exited(code) => *code,
            _ => None,
        }
    }
}

#[derive(Debug)]
struct ArtifactReference {
    id: String,
    sha256: String,
}

#[derive(Debug)]
struct ShellExecution {
    completion: ShellCompletion,
    stdout: String,
    stderr: String,
    stdout_sha256: String,
    stderr_sha256: String,
    truncated: bool,
    artifact: Option<ArtifactReference>,
    duration_ms: u64,
}

impl ShellExecution {
    fn into_tool_result(self, call_id: &str) -> ToolResult {
        let mut output = json!({
            "exit_code": self.completion.exit_code(),
            "stdout": self.stdout,
            "stderr": self.stderr,
            "stdout_sha256": self.stdout_sha256,
            "stderr_sha256": self.stderr_sha256,
            "truncated": self.truncated,
            "duration_ms": self.duration_ms,
        });
        if let Some(artifact) = self.artifact {
            output["artifact_id"] = json!(artifact.id);
            output["artifact_sha256"] = json!(artifact.sha256);
        }

        let (is_error, error_code, message) = match &self.completion {
            ShellCompletion::Exited(Some(0)) => (false, None, None),
            ShellCompletion::Exited(code) => (
                true,
                Some("process_exit".to_owned()),
                Some(format!("shell exited with status {code:?}")),
            ),
            ShellCompletion::TimedOut => (
                true,
                Some("timeout".to_owned()),
                Some("shell command timed out".to_owned()),
            ),
            ShellCompletion::Cancelled => (
                true,
                Some("cancelled".to_owned()),
                Some("shell command was cancelled".to_owned()),
            ),
            ShellCompletion::WaitFailed(error) => (
                true,
                Some("process_exit".to_owned()),
                Some(format!("failed to wait for shell: {error}")),
            ),
        };
        if let (Some(code), Some(message)) = (&error_code, message) {
            output["error"] = json!({ "code": code, "message": message });
        }
        ToolResult {
            call_id: call_id.to_owned(),
            output,
            is_error,
            error_code,
        }
    }
}

fn io_error_code(error: &io::Error) -> &'static str {
    match error.kind() {
        io::ErrorKind::NotFound => "not_found",
        io::ErrorKind::PermissionDenied => "permission_denied",
        io::ErrorKind::InvalidInput | io::ErrorKind::InvalidData => "validation_error",
        _ => "process_exit",
    }
}

fn io_result(call_id: &str, operation: &str, error: io::Error) -> ToolResult {
    ToolResult::error(
        call_id,
        io_error_code(&error),
        format!("failed to {operation}: {error}"),
    )
}

fn error_result(call_id: &str, error: OxidraError) -> ToolResult {
    match error {
        OxidraError::Tool { code, message } => ToolResult::error(call_id, code, message),
        OxidraError::Io(error) => io_result(call_id, "perform tool operation", error),
        OxidraError::Interrupted => {
            ToolResult::error(call_id, "cancelled", "operation interrupted")
        }
        other => ToolResult::error(call_id, "process_exit", other.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn harness() -> (TempDir, TempDir, BuiltinTools) {
        let root = TempDir::new().expect("root tempdir");
        let artifacts = TempDir::new().expect("artifact tempdir");
        let tools = BuiltinTools::new(
            root.path(),
            artifacts.path(),
            artifacts.path().join("memory"),
            true,
            false,
        )
        .expect("construct built-in tools");
        (root, artifacts, tools)
    }

    fn call(name: &str, arguments: Value) -> ToolCall {
        ToolCall {
            id: "call-1".to_owned(),
            name: name.to_owned(),
            arguments,
        }
    }

    #[tokio::test]
    async fn read_rejects_path_escape() {
        let (_root, _artifacts, tools) = harness();
        let outside = tempfile::NamedTempFile::new().expect("outside file");
        std::fs::write(outside.path(), "secret").expect("write outside file");

        let result = tools
            .execute(
                &call("read", json!({ "path": outside.path() })),
                &ToolContext::default(),
            )
            .await;

        assert!(result.is_error);
        assert_eq!(result.error_code.as_deref(), Some("permission_denied"));
    }

    #[tokio::test]
    async fn edit_rejects_stale_hash_without_overwriting() {
        let (root, _artifacts, tools) = harness();
        let path = root.path().join("file.txt");
        std::fs::write(&path, "before\n").expect("write fixture");

        let result = tools
            .execute(
                &call(
                    "edit",
                    json!({
                        "path": "file.txt",
                        "old_text": "before",
                        "new_text": "after",
                        "expected_sha256": "0".repeat(64),
                    }),
                ),
                &ToolContext::default(),
            )
            .await;

        assert!(result.is_error);
        assert_eq!(result.error_code.as_deref(), Some("stale_file"));
        assert_eq!(std::fs::read_to_string(path).unwrap(), "before\n");
    }

    #[tokio::test]
    async fn edit_replaces_exactly_one_match() {
        let (root, _artifacts, tools) = harness();
        let path = root.path().join("file.txt");
        let original = "alpha beta gamma\n";
        std::fs::write(&path, original).expect("write fixture");

        let result = tools
            .execute(
                &call(
                    "edit",
                    json!({
                        "path": "file.txt",
                        "old_text": "beta",
                        "new_text": "delta",
                        "expected_sha256": sha256_hex(original.as_bytes()),
                    }),
                ),
                &ToolContext::default(),
            )
            .await;

        assert!(!result.is_error, "{result:?}");
        assert_eq!(result.output["replaced_count"], 1);
        assert_eq!(
            std::fs::read_to_string(path).unwrap(),
            "alpha delta gamma\n"
        );
    }

    #[tokio::test]
    async fn edit_rejects_multiple_matches() {
        let (root, _artifacts, tools) = harness();
        let path = root.path().join("file.txt");
        let original = "same same";
        std::fs::write(&path, original).expect("write fixture");

        let result = tools
            .execute(
                &call(
                    "edit",
                    json!({
                        "path": "file.txt",
                        "old_text": "same",
                        "new_text": "changed",
                        "expected_sha256": sha256_hex(original.as_bytes()),
                    }),
                ),
                &ToolContext::default(),
            )
            .await;

        assert!(result.is_error);
        assert_eq!(result.error_code.as_deref(), Some("validation_error"));
        assert_eq!(std::fs::read_to_string(path).unwrap(), original);
    }

    #[tokio::test]
    async fn write_creates_utf8_file_and_returns_digest() {
        let (root, _artifacts, tools) = harness();
        std::fs::create_dir(root.path().join("nested")).expect("create parent");
        let content = "hello, 氧化物\n";

        let result = tools
            .execute(
                &call(
                    "write",
                    json!({ "path": "nested/new.txt", "content": content }),
                ),
                &ToolContext::default(),
            )
            .await;

        assert!(!result.is_error, "{result:?}");
        assert_eq!(result.output["path"], "nested/new.txt");
        assert_eq!(result.output["bytes"], content.len());
        assert_eq!(result.output["sha256"], sha256_hex(content.as_bytes()));
        assert_eq!(
            std::fs::read_to_string(root.path().join("nested/new.txt")).unwrap(),
            content
        );
    }

    #[tokio::test]
    async fn write_refuses_overwrite_and_path_escape() {
        let (root, _artifacts, tools) = harness();
        std::fs::write(root.path().join("existing.txt"), "original").expect("fixture");

        let overwrite = tools
            .execute(
                &call(
                    "write",
                    json!({ "path": "existing.txt", "content": "changed" }),
                ),
                &ToolContext::default(),
            )
            .await;
        assert!(overwrite.is_error);
        assert_eq!(overwrite.error_code.as_deref(), Some("already_exists"));
        assert_eq!(
            std::fs::read_to_string(root.path().join("existing.txt")).unwrap(),
            "original"
        );

        for path in ["../escaped.txt", "sub/../../escaped.txt"] {
            let escaped = tools
                .execute(
                    &call("write", json!({ "path": path, "content": "no" })),
                    &ToolContext::default(),
                )
                .await;
            assert!(escaped.is_error, "path unexpectedly accepted: {path}");
            assert_eq!(escaped.error_code.as_deref(), Some("permission_denied"));
        }

        let absolute = root.path().join("absolute.txt");
        let escaped = tools
            .execute(
                &call("write", json!({ "path": absolute, "content": "no" })),
                &ToolContext::default(),
            )
            .await;
        assert!(escaped.is_error);
        assert_eq!(escaped.error_code.as_deref(), Some("permission_denied"));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn write_rejects_symlinked_parent_escape() {
        use std::os::unix::fs::symlink;

        let (root, _artifacts, tools) = harness();
        let outside = TempDir::new().expect("outside tempdir");
        symlink(outside.path(), root.path().join("link")).expect("create symlink");

        let result = tools
            .execute(
                &call(
                    "write",
                    json!({ "path": "link/escaped.txt", "content": "no" }),
                ),
                &ToolContext::default(),
            )
            .await;

        assert!(result.is_error);
        assert_eq!(result.error_code.as_deref(), Some("permission_denied"));
        assert!(!outside.path().join("escaped.txt").exists());
    }

    #[tokio::test]
    async fn write_honors_pre_cancelled_context() {
        let (root, _artifacts, tools) = harness();
        let cancellation = CancellationToken::new();
        cancellation.cancel();
        let result = tools
            .execute(
                &call("write", json!({ "path": "cancelled.txt", "content": "no" })),
                &ToolContext::new(cancellation),
            )
            .await;

        assert!(result.is_error);
        assert_eq!(result.error_code.as_deref(), Some("cancelled"));
        assert!(!root.path().join("cancelled.txt").exists());
    }

    #[tokio::test]
    async fn remember_requires_approval_and_persists_plain_text() {
        let (_root, _artifacts, tools) = harness();
        let call = call("remember", json!({ "content": "prefer focused changes" }));

        let denied = tools.execute(&call, &ToolContext::default()).await;
        assert!(denied.is_error);
        assert_eq!(denied.error_code.as_deref(), Some("approval_required"));
        assert!(tools.memory.list().unwrap().is_empty());

        let approved = ToolContext::default().with_memory_approval(true);
        let result = tools.execute(&call, &approved).await;
        assert!(!result.is_error, "{result:?}");
        let id = result.output["id"].as_str().unwrap();
        let stored = tools.memory.show(id).unwrap();
        assert_eq!(stored.content, "prefer focused changes");
        assert!(matches!(
            stored.provenance,
            crate::memory::MemoryProvenance::Known { .. }
        ));
    }

    #[tokio::test]
    async fn read_truncates_at_line_limit_and_returns_full_hash() {
        use std::fmt::Write as _;

        let (root, _artifacts, tools) = harness();
        let contents = (0..2_100).fold(String::new(), |mut contents, line| {
            writeln!(contents, "line-{line}").expect("write fixture line");
            contents
        });
        std::fs::write(root.path().join("large.txt"), &contents).expect("write fixture");

        let result = tools
            .execute(
                &call("read", json!({ "path": "large.txt" })),
                &ToolContext::default(),
            )
            .await;

        assert!(!result.is_error, "{result:?}");
        assert_eq!(result.output["truncated"], true);
        assert_eq!(result.output["range"]["returned_lines"], 2_000);
        assert_eq!(
            result.output["full_file_sha256"],
            sha256_hex(contents.as_bytes())
        );
        assert!(result.output["text"].as_str().unwrap().len() <= MAX_TOOL_OUTPUT_BYTES);
    }

    #[tokio::test]
    async fn shell_cancellation_returns_promptly() {
        let (_root, _artifacts, tools) = harness();
        let command = if cfg!(windows) {
            "Start-Sleep -Seconds 30"
        } else {
            "sleep 30"
        };
        let call = call("shell", json!({"command": command, "timeout": 60}));
        let cancellation = CancellationToken::new();
        let context = ToolContext::new(cancellation.clone()).with_shell_approval(true);
        let execution = tools.execute(&call, &context);
        tokio::pin!(execution);

        tokio::select! {
            result = &mut execution => panic!("shell exited before cancellation: {result:?}"),
            _ = tokio::time::sleep(Duration::from_millis(200)) => {}
        }
        cancellation.cancel();
        let result = tokio::time::timeout(Duration::from_secs(5), &mut execution)
            .await
            .expect("shell cancellation exceeded five seconds");

        assert!(result.is_error);
        assert_eq!(result.error_code.as_deref(), Some("cancelled"));
    }

    #[test]
    fn definitions_have_closed_object_schemas() {
        let (_root, _artifacts, tools) = harness();
        let definitions = tools.definitions();
        assert_eq!(definitions.len(), 5);
        for definition in definitions {
            assert_eq!(definition.input_schema["type"], "object");
            assert_eq!(definition.input_schema["additionalProperties"], false);
        }
    }
}
