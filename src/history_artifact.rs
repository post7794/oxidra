use std::path::{Path, PathBuf};

use base64::Engine as _;
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::io::AsyncReadExt;
use tokio_util::sync::CancellationToken;

use crate::error::{OxidraError, Result};
use crate::fs_security::open_read_only_no_follow;
use crate::history::{
    HistorySnapshot, MAX_HISTORY_ARTIFACT_SOURCE_BYTES, UNTRUSTED_HISTORY_NOTICE,
    serialized_history_tool_output_bytes,
};
use crate::tools::MAX_ARTIFACT_BYTES;

const MAX_ARTIFACT_METADATA_BYTES: u64 = 64 * 1_024;

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HistoryArtifactStream {
    Stdout,
    Stderr,
}

impl HistoryArtifactStream {
    fn key(self) -> &'static str {
        match self {
            Self::Stdout => "stdout",
            Self::Stderr => "stderr",
        }
    }

    fn file_name(self) -> &'static str {
        match self {
            Self::Stdout => "stdout.bin",
            Self::Stderr => "stderr.bin",
        }
    }
}

fn default_max_bytes() -> usize {
    MAX_HISTORY_ARTIFACT_SOURCE_BYTES
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HistoryArtifactRequest {
    pub artifact_id: String,
    pub stream: HistoryArtifactStream,
    #[serde(default)]
    pub byte_offset: usize,
    #[serde(default = "default_max_bytes")]
    pub max_bytes: usize,
}

pub struct HistoryArtifactReader {
    root: PathBuf,
}

impl HistoryArtifactReader {
    pub fn new(root: impl AsRef<Path>) -> Result<Self> {
        let root = std::fs::canonicalize(root.as_ref())?;
        if !root.is_dir() {
            return Err(OxidraError::Session(format!(
                "artifact root is not a directory: {}",
                root.display()
            )));
        }
        Ok(Self { root })
    }

    pub async fn read(
        &self,
        snapshot: &HistorySnapshot,
        request: &HistoryArtifactRequest,
        call_id: &str,
        output_budget: usize,
        cancellation: &CancellationToken,
    ) -> Result<Value> {
        if request.max_bytes == 0 || request.max_bytes > MAX_HISTORY_ARTIFACT_SOURCE_BYTES {
            return Err(OxidraError::tool(
                "validation_error",
                format!("max_bytes must be between 1 and {MAX_HISTORY_ARTIFACT_SOURCE_BYTES}"),
            ));
        }
        if cancellation.is_cancelled() {
            return Err(OxidraError::Interrupted);
        }
        let grant = snapshot.artifact_grant(&request.artifact_id)?;
        let directory = verified_child_directory(&self.root, &grant.artifact_id).await?;
        let metadata_path = verified_child_file(&directory, "metadata.json").await?;
        let metadata_bytes = match read_regular_file_bounded(
            &metadata_path,
            MAX_ARTIFACT_METADATA_BYTES,
            cancellation,
        )
        .await
        {
            Ok(bytes) => bytes,
            Err(ArtifactFileReadError::Cancelled) => return Err(OxidraError::Interrupted),
            Err(ArtifactFileReadError::NotRegular) => {
                return integrity_error("artifact metadata is not a regular file");
            }
            Err(ArtifactFileReadError::TooLarge) => {
                return integrity_error("artifact metadata exceeds the 64 KiB limit");
            }
            Err(ArtifactFileReadError::Io(error)) => return Err(error.into()),
        };
        if sha256_hex(&metadata_bytes) != grant.metadata_sha256 {
            return integrity_error("artifact metadata digest does not match the journal grant");
        }
        let metadata: Value = serde_json::from_slice(&metadata_bytes)
            .map_err(|_| integrity_error_value("artifact metadata is not valid JSON"))?;
        let schema = metadata
            .get("schema")
            .and_then(Value::as_u64)
            .ok_or_else(|| integrity_error_value("artifact metadata has no integer schema"))?;
        if !matches!(schema, 1 | 2) {
            return integrity_error(format!("unsupported artifact metadata schema {schema}"));
        }
        if metadata.get("kind").and_then(Value::as_str) != Some("shell_output") {
            return integrity_error("artifact metadata kind is not shell_output");
        }
        let stream = metadata
            .get(request.stream.key())
            .and_then(Value::as_object)
            .ok_or_else(|| integrity_error_value("artifact metadata has no requested stream"))?;
        if stream.get("file").and_then(Value::as_str) != Some(request.stream.file_name()) {
            return integrity_error("artifact stream uses an unexpected file name");
        }
        let stored_bytes = required_u64(stream.get("stored_bytes"), "stored_bytes")?;
        if stored_bytes > MAX_ARTIFACT_BYTES {
            return integrity_error(format!(
                "artifact stored stream exceeds the {MAX_ARTIFACT_BYTES}-byte limit"
            ));
        }
        let original_bytes = required_u64(stream.get("bytes"), "bytes")?;
        let artifact_truncated = stream
            .get("artifact_truncated")
            .and_then(Value::as_bool)
            .ok_or_else(|| {
                integrity_error_value("artifact stream has no artifact_truncated flag")
            })?;
        let full_sha256 = required_digest(stream.get("sha256"), "sha256")?;
        let stored_sha256 = match schema {
            2 => required_digest(stream.get("stored_sha256"), "stored_sha256")?,
            1 if artifact_truncated => {
                return Err(OxidraError::tool(
                    "artifact_integrity_unverifiable",
                    "legacy truncated artifact has no stored stream digest",
                ));
            }
            1 => full_sha256.clone(),
            _ => unreachable!(),
        };
        if !artifact_truncated && (stored_bytes != original_bytes || stored_sha256 != full_sha256) {
            return integrity_error("untruncated artifact stream metadata is inconsistent");
        }

        let stream_path = verified_child_file(&directory, request.stream.file_name()).await?;
        let bytes = match read_regular_file_bounded(&stream_path, stored_bytes, cancellation).await
        {
            Ok(bytes) => bytes,
            Err(ArtifactFileReadError::Cancelled) => return Err(OxidraError::Interrupted),
            Err(ArtifactFileReadError::NotRegular) => {
                return integrity_error("artifact stream is not a regular file");
            }
            Err(ArtifactFileReadError::TooLarge) => {
                return integrity_error("artifact stream length does not match metadata");
            }
            Err(ArtifactFileReadError::Io(error)) => return Err(error.into()),
        };
        if u64::try_from(bytes.len()).unwrap_or(u64::MAX) != stored_bytes {
            return integrity_error("artifact stream length does not match metadata");
        }
        if sha256_hex(&bytes) != stored_sha256 {
            return integrity_error("artifact stream digest does not match metadata");
        }
        if request.byte_offset > bytes.len() {
            return Err(OxidraError::tool(
                "validation_error",
                "byte_offset is beyond the stored artifact stream",
            ));
        }

        let maximum_end = request
            .byte_offset
            .saturating_add(request.max_bytes)
            .min(bytes.len());
        let mut end = maximum_end;
        loop {
            let output = artifact_output(
                &grant.artifact_id,
                grant.source_seq,
                &grant.turn_id,
                request.stream,
                request.byte_offset,
                end,
                bytes.len(),
                &bytes[request.byte_offset..end],
            );
            if serialized_history_tool_output_bytes(call_id, &output)? <= output_budget {
                return Ok(output);
            }
            if end == request.byte_offset {
                return Err(OxidraError::tool(
                    "history_quota_exhausted",
                    "remaining history quota cannot fit an artifact result",
                ));
            }
            let length = end - request.byte_offset;
            end = request.byte_offset + length.saturating_mul(3) / 4;
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn artifact_output(
    artifact_id: &str,
    source_seq: u64,
    turn_id: &str,
    stream: HistoryArtifactStream,
    start: usize,
    end: usize,
    total: usize,
    bytes: &[u8],
) -> Value {
    json!({
        "notice": UNTRUSTED_HISTORY_NOTICE,
        "artifact_id": artifact_id,
        "source_seq": source_seq,
        "turn_id": turn_id,
        "stream": stream.key(),
        "encoding": "base64",
        "byte_range": {"start": start, "end": end, "stored_total": total},
        "data": base64::engine::general_purpose::STANDARD.encode(bytes),
        "eof": end == total,
        "next_byte_offset": (end < total).then_some(end),
    })
}

async fn verified_child_directory(root: &Path, name: &str) -> Result<PathBuf> {
    let candidate = root.join(name);
    let metadata = tokio::fs::symlink_metadata(&candidate).await?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return integrity_error("artifact directory is missing or is a symbolic link");
    }
    let canonical = tokio::fs::canonicalize(&candidate).await?;
    if canonical.parent() != Some(root) {
        return integrity_error("artifact directory resolves outside the session artifact root");
    }
    Ok(canonical)
}

async fn verified_child_file(directory: &Path, name: &str) -> Result<PathBuf> {
    let candidate = directory.join(name);
    let metadata = tokio::fs::symlink_metadata(&candidate).await?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return integrity_error("artifact file is missing or is a symbolic link");
    }
    let canonical = tokio::fs::canonicalize(&candidate).await?;
    if canonical.parent() != Some(directory) {
        return integrity_error("artifact file resolves outside its artifact directory");
    }
    Ok(canonical)
}

#[derive(Debug)]
enum ArtifactFileReadError {
    Cancelled,
    NotRegular,
    TooLarge,
    Io(std::io::Error),
}

impl From<std::io::Error> for ArtifactFileReadError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

async fn read_regular_file_bounded(
    path: &Path,
    max_bytes: u64,
    cancellation: &CancellationToken,
) -> std::result::Result<Vec<u8>, ArtifactFileReadError> {
    let file = tokio::select! {
        _ = cancellation.cancelled() => return Err(ArtifactFileReadError::Cancelled),
        result = open_read_only_no_follow(path) => result?,
    };
    let metadata = file.metadata()?;
    if !metadata.file_type().is_file() {
        return Err(ArtifactFileReadError::NotRegular);
    }
    if metadata.len() > max_bytes {
        return Err(ArtifactFileReadError::TooLarge);
    }
    let capacity = usize::try_from(metadata.len().min(max_bytes)).unwrap_or(usize::MAX);
    let mut bytes = Vec::with_capacity(capacity);
    let mut limited = tokio::fs::File::from_std(file).take(max_bytes.saturating_add(1));
    tokio::select! {
        _ = cancellation.cancelled() => return Err(ArtifactFileReadError::Cancelled),
        result = limited.read_to_end(&mut bytes) => result?,
    };
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > max_bytes {
        return Err(ArtifactFileReadError::TooLarge);
    }
    Ok(bytes)
}

fn required_u64(value: Option<&Value>, field: &str) -> Result<u64> {
    value
        .and_then(Value::as_u64)
        .ok_or_else(|| integrity_error_value(format!("artifact stream has invalid {field}")))
}

fn required_digest(value: Option<&Value>, field: &str) -> Result<String> {
    let digest = value
        .and_then(Value::as_str)
        .filter(|digest| digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit()));
    digest
        .map(str::to_ascii_lowercase)
        .ok_or_else(|| integrity_error_value(format!("artifact stream has invalid {field}")))
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn integrity_error<T>(message: impl Into<String>) -> Result<T> {
    Err(integrity_error_value(message))
}

fn integrity_error_value(message: impl Into<String>) -> OxidraError {
    OxidraError::tool("artifact_integrity_error", message)
}

#[cfg(test)]
mod tests {
    use serde_json::Map;
    use tempfile::TempDir;

    use super::*;
    use crate::compaction::{Checkpoint, validate_checkpoint_chain};
    use crate::history::MAX_HISTORY_TOOL_OUTPUT_BYTES;
    use crate::session::JournalEvent;

    fn event(seq: u64, turn_id: Option<&str>, kind: &str, data: Value) -> JournalEvent {
        JournalEvent {
            schema: 1,
            seq,
            ts: chrono::DateTime::from_timestamp(0, 0).unwrap(),
            kind: kind.to_owned(),
            session_id: "session".to_owned(),
            turn_id: turn_id.map(str::to_owned),
            data,
        }
    }

    fn snapshot_with_artifact(metadata_sha256: &str) -> HistorySnapshot {
        let events = vec![
            event(
                1,
                Some("turn"),
                "user.message",
                json!({"item":{"role":"user","content":"x"}}),
            ),
            event(
                2,
                Some("turn"),
                "response.completed",
                json!({"output_items":[{"type":"function_call","call_id":"call","name":"shell","arguments":"{}"}]}),
            ),
            event(
                3,
                Some("turn"),
                "tool.completed",
                json!({"call_id":"call","tool":"shell","output":{"artifact_id":"artifact-1","artifact_sha256":metadata_sha256}}),
            ),
            event(
                4,
                Some("turn"),
                "response.completed",
                json!({"output_items":[{"type":"message","role":"assistant","content":[{"type":"output_text","text":"done"}]}]}),
            ),
            event(
                5,
                Some("turn"),
                "turn.completed",
                json!({"turn_boundary_version":1,"covers_from_seq":1,"final_response_seq":4,"covers_through_seq":5}),
            ),
        ];
        let checkpoint = Checkpoint {
            attempt_id: "attempt".to_owned(),
            checkpoint_id: "checkpoint".to_owned(),
            parent_checkpoint_id: None,
            covers_through_seq: 5,
            source_digest: "0".repeat(64),
            summary: "summary".to_owned(),
            model: "model".to_owned(),
            prompt_version: 1,
            summary_envelope_version: 1,
            source_projection_version: 1,
            turn_boundary_validator_version: 1,
            source_digest_version: 1,
            usage_contract_version: 1,
            usage: json!({"input_tokens":1,"output_tokens":1,"total_tokens":2}),
            duration_ms: 1,
            raw_response: json!({"id":"r","status":"completed","usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2},"output":[{"type":"message","role":"assistant","content":[{"type":"output_text","text":"summary"}]}]}),
            journal_seq: 7,
            extra: Map::new(),
        };
        let mut all = events;
        let source = crate::compaction::build_compaction_source(&all, None, 5).unwrap();
        let digest = source.digest().unwrap();
        all.push(event(6, None, "compaction.started", json!({"attempt_id":"attempt","parent_checkpoint_id":null,"covers_through_seq":5,"source":source,"source_digest":digest,"instructions":crate::compaction::compaction_instructions(1).unwrap(),"prompt_version":1,"summary_envelope_version":1,"source_projection_version":1,"turn_boundary_validator_version":1,"source_digest_version":1,"usage_contract_version":1,"model":"model"})));
        let mut checkpoint = checkpoint;
        checkpoint.source_digest = digest;
        all.push(event(
            7,
            None,
            "compaction.checkpoint",
            serde_json::to_value(checkpoint).unwrap(),
        ));
        let chain = validate_checkpoint_chain(&all).unwrap();
        HistorySnapshot::build(&all, &chain).unwrap()
    }

    #[tokio::test]
    async fn reads_a_verified_v2_binary_chunk_and_bounds_the_final_output() {
        let temp = TempDir::new().unwrap();
        let directory = temp.path().join("artifact-1");
        std::fs::create_dir(&directory).unwrap();
        let stdout = [0, 1, 2, 250, 251, 252];
        let stderr = [];
        std::fs::write(directory.join("stdout.bin"), stdout).unwrap();
        std::fs::write(directory.join("stderr.bin"), stderr).unwrap();
        let metadata = json!({
            "schema":2,"kind":"shell_output",
            "stdout":{"file":"stdout.bin","bytes":6,"stored_bytes":6,"artifact_truncated":false,"sha256":sha256_hex(&stdout),"stored_sha256":sha256_hex(&stdout)},
            "stderr":{"file":"stderr.bin","bytes":0,"stored_bytes":0,"artifact_truncated":false,"sha256":sha256_hex(&stderr),"stored_sha256":sha256_hex(&stderr)}
        });
        let metadata_bytes = serde_json::to_vec_pretty(&metadata).unwrap();
        std::fs::write(directory.join("metadata.json"), &metadata_bytes).unwrap();
        let snapshot = snapshot_with_artifact(&sha256_hex(&metadata_bytes));
        let reader = HistoryArtifactReader::new(temp.path()).unwrap();
        let output = reader
            .read(
                &snapshot,
                &HistoryArtifactRequest {
                    artifact_id: "artifact-1".to_owned(),
                    stream: HistoryArtifactStream::Stdout,
                    byte_offset: 1,
                    max_bytes: 4,
                },
                "history-call",
                12_288,
                &CancellationToken::new(),
            )
            .await
            .unwrap();
        assert_eq!(
            output["data"],
            base64::engine::general_purpose::STANDARD.encode([1, 2, 250, 251])
        );
        assert_eq!(output["next_byte_offset"], 5);
        assert!(serialized_history_tool_output_bytes("history-call", &output).unwrap() <= 12_288);
    }

    #[tokio::test]
    async fn rejects_tampered_or_unverifiable_artifacts() {
        let temp = TempDir::new().unwrap();
        let directory = temp.path().join("artifact-1");
        std::fs::create_dir(&directory).unwrap();
        std::fs::write(directory.join("stdout.bin"), b"stored").unwrap();
        std::fs::write(directory.join("stderr.bin"), b"").unwrap();
        let metadata = json!({"schema":1,"kind":"shell_output","stdout":{"file":"stdout.bin","bytes":9,"stored_bytes":6,"artifact_truncated":true,"sha256":"0".repeat(64)},"stderr":{"file":"stderr.bin","bytes":0,"stored_bytes":0,"artifact_truncated":false,"sha256":sha256_hex(b"")}});
        let metadata_bytes = serde_json::to_vec_pretty(&metadata).unwrap();
        std::fs::write(directory.join("metadata.json"), &metadata_bytes).unwrap();
        let snapshot = snapshot_with_artifact(&sha256_hex(&metadata_bytes));
        let reader = HistoryArtifactReader::new(temp.path()).unwrap();
        let error = reader
            .read(
                &snapshot,
                &HistoryArtifactRequest {
                    artifact_id: "artifact-1".to_owned(),
                    stream: HistoryArtifactStream::Stdout,
                    byte_offset: 0,
                    max_bytes: 8,
                },
                "call",
                12_288,
                &CancellationToken::new(),
            )
            .await
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("artifact_integrity_unverifiable")
        );
    }

    #[tokio::test]
    async fn reads_an_untruncated_v1_artifact() {
        let temp = TempDir::new().unwrap();
        let directory = temp.path().join("artifact-1");
        std::fs::create_dir(&directory).unwrap();
        let stdout = b"legacy-complete";
        std::fs::write(directory.join("stdout.bin"), stdout).unwrap();
        std::fs::write(directory.join("stderr.bin"), b"").unwrap();
        let metadata = json!({
            "schema":1,"kind":"shell_output",
            "stdout":{"file":"stdout.bin","bytes":stdout.len(),"stored_bytes":stdout.len(),"artifact_truncated":false,"sha256":sha256_hex(stdout)},
            "stderr":{"file":"stderr.bin","bytes":0,"stored_bytes":0,"artifact_truncated":false,"sha256":sha256_hex(b"")}
        });
        let metadata_bytes = serde_json::to_vec_pretty(&metadata).unwrap();
        std::fs::write(directory.join("metadata.json"), &metadata_bytes).unwrap();

        let output = HistoryArtifactReader::new(temp.path())
            .unwrap()
            .read(
                &snapshot_with_artifact(&sha256_hex(&metadata_bytes)),
                &HistoryArtifactRequest {
                    artifact_id: "artifact-1".to_owned(),
                    stream: HistoryArtifactStream::Stdout,
                    byte_offset: 0,
                    max_bytes: MAX_HISTORY_ARTIFACT_SOURCE_BYTES,
                },
                "call",
                MAX_HISTORY_TOOL_OUTPUT_BYTES,
                &CancellationToken::new(),
            )
            .await
            .unwrap();
        assert_eq!(
            output["data"],
            base64::engine::general_purpose::STANDARD.encode(stdout)
        );
        assert_eq!(output["eof"], true);
    }

    #[tokio::test]
    async fn rejects_v2_metadata_and_stream_tampering() {
        for tamper_metadata in [false, true] {
            let temp = TempDir::new().unwrap();
            let directory = temp.path().join("artifact-1");
            std::fs::create_dir(&directory).unwrap();
            let stdout = b"original";
            std::fs::write(directory.join("stdout.bin"), stdout).unwrap();
            std::fs::write(directory.join("stderr.bin"), b"").unwrap();
            let metadata = json!({
                "schema":2,"kind":"shell_output",
                "stdout":{"file":"stdout.bin","bytes":stdout.len(),"stored_bytes":stdout.len(),"artifact_truncated":false,"sha256":sha256_hex(stdout),"stored_sha256":sha256_hex(stdout)},
                "stderr":{"file":"stderr.bin","bytes":0,"stored_bytes":0,"artifact_truncated":false,"sha256":sha256_hex(b""),"stored_sha256":sha256_hex(b"")}
            });
            let metadata_bytes = serde_json::to_vec_pretty(&metadata).unwrap();
            std::fs::write(directory.join("metadata.json"), &metadata_bytes).unwrap();
            let snapshot = snapshot_with_artifact(&sha256_hex(&metadata_bytes));
            if tamper_metadata {
                let mut changed = metadata.clone();
                changed["command"] = json!("tampered");
                std::fs::write(
                    directory.join("metadata.json"),
                    serde_json::to_vec_pretty(&changed).unwrap(),
                )
                .unwrap();
            } else {
                std::fs::write(directory.join("stdout.bin"), b"modified").unwrap();
            }

            let error = HistoryArtifactReader::new(temp.path())
                .unwrap()
                .read(
                    &snapshot,
                    &HistoryArtifactRequest {
                        artifact_id: "artifact-1".to_owned(),
                        stream: HistoryArtifactStream::Stdout,
                        byte_offset: 0,
                        max_bytes: 8,
                    },
                    "call",
                    MAX_HISTORY_TOOL_OUTPUT_BYTES,
                    &CancellationToken::new(),
                )
                .await
                .unwrap_err();
            assert!(
                matches!(error, OxidraError::Tool { code, .. } if code == "artifact_integrity_error")
            );
        }
    }

    #[tokio::test]
    async fn rejects_stream_size_claim_above_artifact_limit_before_reading() {
        let temp = TempDir::new().unwrap();
        let directory = temp.path().join("artifact-1");
        std::fs::create_dir(&directory).unwrap();
        std::fs::write(directory.join("stdout.bin"), b"").unwrap();
        std::fs::write(directory.join("stderr.bin"), b"").unwrap();
        let oversized = MAX_ARTIFACT_BYTES + 1;
        let metadata = json!({
            "schema":2,"kind":"shell_output",
            "stdout":{"file":"stdout.bin","bytes":oversized,"stored_bytes":oversized,"artifact_truncated":false,"sha256":sha256_hex(b""),"stored_sha256":sha256_hex(b"")},
            "stderr":{"file":"stderr.bin","bytes":0,"stored_bytes":0,"artifact_truncated":false,"sha256":sha256_hex(b""),"stored_sha256":sha256_hex(b"")}
        });
        let metadata_bytes = serde_json::to_vec_pretty(&metadata).unwrap();
        std::fs::write(directory.join("metadata.json"), &metadata_bytes).unwrap();

        let error = HistoryArtifactReader::new(temp.path())
            .unwrap()
            .read(
                &snapshot_with_artifact(&sha256_hex(&metadata_bytes)),
                &HistoryArtifactRequest {
                    artifact_id: "artifact-1".to_owned(),
                    stream: HistoryArtifactStream::Stdout,
                    byte_offset: 0,
                    max_bytes: 8,
                },
                "call",
                MAX_HISTORY_TOOL_OUTPUT_BYTES,
                &CancellationToken::new(),
            )
            .await
            .unwrap_err();
        assert!(
            matches!(error, OxidraError::Tool { code, .. } if code == "artifact_integrity_error")
        );
    }

    #[tokio::test]
    async fn rejects_symlinked_artifact_directory() {
        let temp = TempDir::new().unwrap();
        let outside = TempDir::new().unwrap();
        let link = temp.path().join("artifact-1");
        #[cfg(unix)]
        std::os::unix::fs::symlink(outside.path(), &link).unwrap();
        #[cfg(windows)]
        if let Err(error) = std::os::windows::fs::symlink_dir(outside.path(), &link) {
            // Windows can disable unprivileged symlink creation. The runtime
            // check is still compiled and covered on hosts that permit it.
            if error.kind() == std::io::ErrorKind::PermissionDenied
                || error.raw_os_error() == Some(1314)
            {
                return;
            }
            panic!("failed to create test symlink: {error}");
        }

        let error = HistoryArtifactReader::new(temp.path())
            .unwrap()
            .read(
                &snapshot_with_artifact(&"a".repeat(64)),
                &HistoryArtifactRequest {
                    artifact_id: "artifact-1".to_owned(),
                    stream: HistoryArtifactStream::Stdout,
                    byte_offset: 0,
                    max_bytes: 8,
                },
                "call",
                MAX_HISTORY_TOOL_OUTPUT_BYTES,
                &CancellationToken::new(),
            )
            .await
            .unwrap_err();
        assert!(
            matches!(error, OxidraError::Tool { code, .. } if code == "artifact_integrity_error")
        );
    }
}
