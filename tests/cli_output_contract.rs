//! End-to-end contracts for approval, canonical output, display, and exit status.
//! Every process uses an isolated data root and a loopback-only fake Provider.

use std::collections::VecDeque;
use std::fs;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use tempfile::TempDir;

struct Harness {
    _root: TempDir,
    project: PathBuf,
    home: PathBuf,
    data: PathBuf,
}

impl Harness {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let project = root.path().join("project");
        let home = root.path().join("home");
        fs::create_dir_all(&project).unwrap();
        for subdir in ["local", "roaming", "config", "state", "data"] {
            fs::create_dir_all(home.join(subdir)).unwrap();
        }
        let data = if cfg!(windows) {
            home.join("local/oxidra")
        } else if cfg!(target_os = "macos") {
            home.join("Library/Application Support/oxidra")
        } else {
            home.join("state/oxidra")
        };
        Self {
            _root: root,
            project,
            home,
            data,
        }
    }

    fn run(&self, server: &FakeProvider, arguments: &[&str], input: Option<&str>) -> Output {
        let mut command = Command::new(env!("CARGO_BIN_EXE_oxidra"));
        command
            .arg("--cwd")
            .arg(&self.project)
            .args(arguments)
            .env("API_KEY", "contract-test-fake-key")
            .env("API_BASE_URL", format!("http://{}/v1/", server.address))
            .env("HOME", &self.home)
            .env("USERPROFILE", &self.home)
            .env("LOCALAPPDATA", self.home.join("local"))
            .env("APPDATA", self.home.join("roaming"))
            .env("XDG_CONFIG_HOME", self.home.join("config"))
            .env("XDG_STATE_HOME", self.home.join("state"))
            .env("XDG_DATA_HOME", self.home.join("data"))
            .env("NO_PROXY", "127.0.0.1,localhost")
            .env("no_proxy", "127.0.0.1,localhost");
        for key in [
            "MODEL",
            "OPENAI_MODEL",
            "OPENAI_API_KEY",
            "OPENAI_BASE_URL",
            "OXIDRA_CONTEXT_WINDOW",
            "OXIDRA_RESERVE_TOKENS",
        ] {
            command.env_remove(key);
        }
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        // Drain both pipes before writing input; an untruncated approval can
        // exceed pipe capacity and must not deadlock this test harness.
        let stdout = drain(child.stdout.take().unwrap());
        let stderr = drain(child.stderr.take().unwrap());
        let mut stdin = child.stdin.take().unwrap();
        if let Some(input) = input {
            stdin.write_all(input.as_bytes()).unwrap();
        }
        drop(stdin);
        let deadline = Instant::now() + Duration::from_secs(20);
        let (status, timed_out) = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break (status, false);
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                break (child.wait().unwrap(), true);
            }
            thread::sleep(Duration::from_millis(10));
        };
        let output = Output {
            status,
            stdout: stdout.join().unwrap(),
            stderr: stderr.join().unwrap(),
        };
        assert!(
            !timed_out,
            "CLI timed out: {:?}",
            String::from_utf8_lossy(&output.stderr)
        );
        output
    }

    fn session_id(&self) -> String {
        let journals = fs::read_dir(self.data.join("sessions"))
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| {
                path.extension()
                    .is_some_and(|extension| extension == "jsonl")
            })
            .collect::<Vec<_>>();
        assert_eq!(journals.len(), 1);
        journals[0]
            .file_stem()
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned()
    }

    fn events(&self) -> Vec<Value> {
        fs::read_to_string(
            self.data
                .join("sessions")
                .join(format!("{}.jsonl", self.session_id())),
        )
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
    }

    fn memories(&self) -> Vec<PathBuf> {
        fs::read_dir(self.data.join("memory"))
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| path.extension().is_some_and(|extension| extension == "md"))
            .collect()
    }
}

fn drain(mut reader: impl Read + Send + 'static) -> thread::JoinHandle<Vec<u8>> {
    thread::spawn(move || {
        let mut bytes = Vec::new();
        reader.read_to_end(&mut bytes).unwrap();
        bytes
    })
}

struct FakeProvider {
    address: SocketAddr,
    stop: Arc<AtomicBool>,
    requests: Arc<Mutex<Vec<Value>>>,
    expected_requests: usize,
    worker: Option<thread::JoinHandle<io::Result<()>>>,
}

impl FakeProvider {
    fn new(responses: Vec<String>) -> Self {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let address = listener.local_addr().unwrap();
        listener.set_nonblocking(true).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let expected_requests = responses.len();
        let worker = {
            let stop = Arc::clone(&stop);
            let requests = Arc::clone(&requests);
            thread::spawn(move || {
                let mut responses = VecDeque::from(responses);
                while !stop.load(Ordering::Acquire) {
                    let (mut stream, _) = match listener.accept() {
                        Ok(connection) => connection,
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(5));
                            continue;
                        }
                        Err(error) => return Err(error),
                    };
                    stream.set_nonblocking(false)?;
                    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
                    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
                    requests.lock().unwrap().push(read_request(&mut stream)?);
                    let body = responses
                        .pop_front()
                        .ok_or_else(|| io::Error::other("unexpected extra Provider request"))?;
                    write!(
                        stream,
                        "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    )?;
                    stream.flush()?;
                }
                Ok(())
            })
        };
        Self {
            address,
            stop,
            requests,
            expected_requests,
            worker: Some(worker),
        }
    }

    fn finish(mut self) -> Vec<Value> {
        self.stop.store(true, Ordering::Release);
        self.worker.take().unwrap().join().unwrap().unwrap();
        let requests = self.requests.lock().unwrap().clone();
        assert_eq!(requests.len(), self.expected_requests);
        requests
    }
}

impl Drop for FakeProvider {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

fn read_request(stream: &mut TcpStream) -> io::Result<Value> {
    let mut reader = BufReader::new(stream);
    let mut content_length = None;
    let mut header_bytes = 0;
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line)? == 0 {
            return Err(io::Error::other("incomplete request headers"));
        }
        header_bytes += line.len();
        if header_bytes > 128 * 1024 {
            return Err(io::Error::other("request headers too large"));
        }
        if line == "\r\n" {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            if name.eq_ignore_ascii_case("content-length") {
                content_length = Some(value.trim().parse::<usize>().map_err(io::Error::other)?);
            }
        }
    }
    let length = content_length.ok_or_else(|| io::Error::other("missing Content-Length"))?;
    if length > 1024 * 1024 {
        return Err(io::Error::other("request body too large for fixture"));
    }
    let mut bytes = vec![0; length];
    reader.read_exact(&mut bytes)?;
    serde_json::from_slice(&bytes).map_err(io::Error::other)
}

fn sse(kind: &str, payload: Value) -> String {
    format!("event: {kind}\ndata: {payload}\n\n")
}

fn message(text: &str) -> Value {
    json!({
        "type": "message",
        "role": "assistant",
        "content": [{"type": "output_text", "text": text}],
    })
}

fn completed(items: Vec<Value>) -> String {
    sse(
        "response.completed",
        json!({
            "type": "response.completed",
            "response": {
                "id": "response-contract",
                "status": "completed",
                "output": items,
                "usage": {"input_tokens": 1, "output_tokens": 1, "total_tokens": 2},
            },
        }),
    )
}

fn tool(name: &str, arguments: Value, id: &str) -> String {
    completed(vec![json!({
        "type": "function_call",
        "name": name,
        "call_id": id,
        "arguments": arguments.to_string(),
    })])
}

fn failing_reads() -> Vec<String> {
    (0..3)
        .map(|index| {
            tool(
                "read",
                json!({"path": "missing.txt"}),
                &format!("read-{index}"),
            )
        })
        .collect()
}

#[test]
fn memory_approval_displays_the_complete_content_before_consent_and_persists_it_exactly() {
    let harness = Harness::new();
    let content = format!(
        "{}APPROVAL_TAIL_中文\n\u{1b}[2J\u{202e}\\u{{202e}}",
        "Visible memory line.\n".repeat(400)
    );
    let server = FakeProvider::new(vec![
        tool("remember", json!({"content": content}), "remember-1"),
        completed(vec![message("Saved.")]),
        completed(vec![message("Resumed.")]),
    ]);
    let output = harness.run(&server, &[], Some("remember this\ny\nexit\n"));
    assert!(output.status.success());
    let stderr = String::from_utf8(output.stderr).unwrap();
    let approval_end = stderr.find("Remember this for future sessions?").unwrap();
    let quoted_content = serde_json::to_string(&content)
        .unwrap()
        .replace('\u{202e}', "\\u{202e}");
    assert!(
        stderr[..approval_end].contains(&quoted_content),
        "the approval preview must include the complete escaped body before asking for consent"
    );
    assert!(!stderr[..approval_end].contains("<truncated>"));
    assert!(!stderr[..approval_end].contains('\u{1b}'));
    assert!(!stderr[..approval_end].contains('\u{202e}'));
    let memories = harness.memories();
    assert_eq!(memories.len(), 1);
    assert!(
        fs::read_to_string(&memories[0])
            .unwrap()
            .ends_with(&content)
    );
    let session = harness.session_id();
    let resumed = harness.run(&server, &["--resume", &session, "-p", "continue"], None);
    assert!(resumed.status.success());
    let requests = server.finish();
    assert!(
        requests[2]["instructions"]
            .as_str()
            .unwrap()
            .contains(&content)
    );
}

#[test]
fn declined_or_eof_memory_approval_never_persists_content() {
    for input in ["remember this\nn\nexit\n", "remember this\n"] {
        let harness = Harness::new();
        let server = FakeProvider::new(vec![
            tool(
                "remember",
                json!({"content": "Do not persist without consent."}),
                "remember-1",
            ),
            completed(vec![message("Not saved.")]),
        ]);
        let output = harness.run(&server, &[], Some(input));
        server.finish();
        assert!(
            output.status.success(),
            "approval case {input:?} failed: {:?}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(harness.memories().is_empty());
        assert!(harness.events().iter().any(|event| {
            event["kind"] == "tool.completed" && event["data"]["error_code"] == "approval_required"
        }));
    }
}

#[test]
fn empty_terminal_text_cannot_revive_deltas_in_display_journal_or_resume() {
    const STALE: &str = "STREAM_ONLY_NOT_IN_CANONICAL_OUTPUT";
    for interactive in [false, true] {
        let harness = Harness::new();
        let response = sse(
            "response.output_text.delta",
            json!({"type": "response.output_text.delta", "delta": STALE}),
        ) + &completed(vec![message("")]);
        let server = FakeProvider::new(vec![response, completed(vec![message("Resumed.")])]);
        let output = if interactive {
            harness.run(&server, &[], Some("answer\nexit\n"))
        } else {
            harness.run(&server, &["-p", "answer"], None)
        };
        assert!(output.status.success());
        assert!(!String::from_utf8_lossy(&output.stdout).contains(STALE));
        let events = harness.events();
        let response = events
            .iter()
            .find(|event| event["kind"] == "response.completed")
            .unwrap();
        assert_eq!(response["data"]["text"], "");
        assert_eq!(response["data"]["output_items"], json!([message("")]));
        let session = harness.session_id();
        let resumed = harness.run(&server, &["--resume", &session, "-p", "continue"], None);
        assert!(resumed.status.success());
        let requests = server.finish();
        assert!(
            requests[1]["input"]
                .as_array()
                .unwrap()
                .contains(&message(""))
        );
        assert!(!requests[1]["input"].to_string().contains(STALE));
    }
}

#[test]
fn final_text_is_terminal_safe_in_both_cli_modes_without_mutating_journal_or_resume() {
    const RAW: &str =
        "heading\n\t中文🙂\r\n\x1b[2J\x1b]52;c;YQ==\x07\u{009b}31m\rOVER\x08\u{202e}end";
    const DISPLAY: &str = "heading\n\t中文🙂\n\\x1b[2J\\x1b]52;c;YQ==\\u{0007}\\u{009b}31m\\rOVER\\u{0008}\\u{202e}end\n";
    for interactive in [false, true] {
        let harness = Harness::new();
        let server = FakeProvider::new(vec![
            completed(vec![message(RAW)]),
            completed(vec![message("Resumed.")]),
        ]);
        let output = if interactive {
            harness.run(&server, &[], Some("answer\nexit\n"))
        } else {
            harness.run(&server, &["-p", "answer"], None)
        };
        assert!(output.status.success());
        assert_eq!(output.stdout, DISPLAY.as_bytes());
        let events = harness.events();
        let response = events
            .iter()
            .find(|event| event["kind"] == "response.completed")
            .unwrap();
        assert_eq!(response["data"]["text"], RAW);
        assert_eq!(
            response["data"]["raw_response"]["output"],
            json!([message(RAW)])
        );
        let session = harness.session_id();
        let resumed = harness.run(&server, &["--resume", &session, "-p", "continue"], None);
        assert!(resumed.status.success());
        let requests = server.finish();
        assert!(
            requests[1]["input"]
                .as_array()
                .unwrap()
                .contains(&message(RAW))
        );
    }
}

#[test]
fn stalled_batch_turn_has_nonzero_exit_and_no_success_stdout() {
    let harness = Harness::new();
    let server = FakeProvider::new(failing_reads());
    let output = harness.run(&server, &["-p", "read a missing file"], None);
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("stalled"));
    let events = harness.events();
    assert!(events.iter().any(|event| event["kind"] == "agent.stalled"));
    assert!(!events.iter().any(|event| event["kind"] == "turn.completed"));
    server.finish();
}

#[test]
fn stalled_pending_retry_has_nonzero_exit_and_can_still_be_retried() {
    let harness = Harness::new();
    let mut responses = vec![sse(
        "error",
        json!({"type": "error", "code": "context_length_exceeded", "message": "fixture limit"}),
    )];
    responses.extend(failing_reads());
    responses.push(completed(vec![message("Recovered.")]));
    let server = FakeProvider::new(responses);
    let initial = harness.run(&server, &["-p", "original prompt"], None);
    assert_eq!(initial.status.code(), Some(4));
    let session = harness.session_id();
    let retry = harness.run(&server, &["--resume", &session, "--retry-pending"], None);
    assert_eq!(retry.status.code(), Some(1));
    assert!(retry.stdout.is_empty());
    assert!(String::from_utf8_lossy(&retry.stderr).contains("stalled"));
    let recovered = harness.run(&server, &["--resume", &session, "--retry-pending"], None);
    assert!(recovered.status.success());
    assert_eq!(recovered.stdout, b"Recovered.\n");
    let events = harness.events();
    assert_eq!(
        events
            .iter()
            .filter(|event| event["kind"] == "user.message")
            .count(),
        1
    );
    assert_eq!(
        events
            .iter()
            .filter(|event| event["kind"] == "turn.retry_started")
            .count(),
        2
    );
    server.finish();
}

#[test]
fn stalled_interactive_turn_keeps_the_repl_usable() {
    let harness = Harness::new();
    let mut responses = failing_reads();
    responses.push(completed(vec![message("Next turn succeeded.")]));
    let server = FakeProvider::new(responses);
    let output = harness.run(
        &server,
        &[],
        Some("read missing file\ntry something else\nexit\n"),
    );
    server.finish();
    assert!(
        output.status.success(),
        "interactive stall failed: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, b"Next turn succeeded.\n");
    assert!(String::from_utf8_lossy(&output.stderr).contains("stalled"));
    let events = harness.events();
    assert_eq!(
        events
            .iter()
            .filter(|event| event["kind"] == "user.message")
            .count(),
        2
    );
    assert_eq!(
        events
            .iter()
            .filter(|event| event["kind"] == "turn.completed")
            .count(),
        1
    );
}

#[test]
fn tool_logs_are_safe_in_both_cli_modes_without_mutating_results() {
    const RAW: &str = "heading\n\t中文🙂\r\n\x1b[2J\u{009b}31m\u{202e}\u{200b}end";
    for interactive in [false, true] {
        for raw in [RAW.to_owned(), format!("{RAW}{}", "\u{202e}".repeat(600))] {
            let harness = Harness::new();
            fs::write(harness.project.join("controls.txt"), &raw).unwrap();
            let server = FakeProvider::new(vec![
                tool("read", json!({"path": "controls.txt"}), "read-controls"),
                completed(vec![message("Read.")]),
            ]);
            let output = if interactive {
                harness.run(&server, &[], Some("read file\nexit\n"))
            } else {
                harness.run(&server, &["-p", "read file"], None)
            };
            assert!(
                output.status.success(),
                "{:?}",
                String::from_utf8_lossy(&output.stderr)
            );
            assert_eq!(output.stdout, b"Read.\n");
            let stderr = String::from_utf8(output.stderr).unwrap();
            for control in ['\x1b', '\u{009b}', '\u{202e}', '\u{200b}'] {
                assert!(!stderr.contains(control), "unsafe control {control:?}");
            }
            let log = stderr
                .lines()
                .find_map(|line| line.strip_prefix("[tool:ok] read "))
                .unwrap();
            assert!(
                log.len() <= 4 * 1024,
                "budget applies after escaping, including the marker"
            );
            let events = harness.events();
            let output = &events
                .iter()
                .find(|e| e["kind"] == "tool.completed")
                .unwrap()["data"]["output"];
            assert_eq!(output["text"], raw);
            let safe = serde_json::to_string(output)
                .unwrap()
                .replace('\u{009b}', "\\u{009b}")
                .replace('\u{202e}', "\\u{202e}")
                .replace('\u{200b}', "\\u{200b}");
            if safe.len() <= 4 * 1024 {
                assert_eq!(log, safe);
            } else {
                assert!(safe.starts_with(log.strip_suffix("...<truncated>").unwrap()));
            }
            let requests = server.finish();
            let result = requests[1]["input"]
                .as_array()
                .unwrap()
                .iter()
                .find(|item| {
                    item["type"] == "function_call_output" && item["call_id"] == "read-controls"
                })
                .unwrap();
            assert_eq!(
                serde_json::from_str::<Value>(result["output"].as_str().unwrap()).unwrap(),
                *output
            );
        }
    }
}

#[test]
fn successful_edit_displays_a_safe_plain_diff_after_completion_in_both_cli_modes() {
    use sha2::{Digest, Sha256};
    const OLD: &str = "old\u{009b}31m\u{202e}\u{200b}\x1b[2J\n";
    const NEW: &str = "new\u{2066}中文\x1b]52;c;YQ==\x07\n";
    const DIFF: &str = "--- edit.txt\n+++ edit.txt\n@@ exact replacement @@\n-old\\u{009b}31m\\u{202e}\\u{200b}\\x1b[2J\n+new\\u{2066}中文\\x1b]52;c;YQ==\\u{0007}\n";
    for interactive in [false, true] {
        let harness = Harness::new();
        fs::write(harness.project.join("edit.txt"), OLD).unwrap();
        let arguments = json!({
            "path": "edit.txt", "old_text": OLD, "new_text": NEW,
            "expected_sha256": hex::encode(Sha256::digest(OLD.as_bytes())),
        });
        let server = FakeProvider::new(vec![
            tool("edit", arguments.clone(), "edit-controls"),
            completed(vec![message("Edited.")]),
        ]);
        let output = if interactive {
            harness.run(&server, &[], Some("edit file\nexit\n"))
        } else {
            harness.run(&server, &["-p", "edit file"], None)
        };
        assert!(
            output.status.success(),
            "{:?}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(output.stdout, b"Edited.\n");
        assert_eq!(
            fs::read_to_string(harness.project.join("edit.txt")).unwrap(),
            NEW
        );
        let stderr = String::from_utf8(output.stderr).unwrap();
        let completed = stderr.find("[tool:ok] edit ").unwrap();
        let diff = stderr
            .find(DIFF)
            .expect("the production CLI must display the applied diff");
        assert!(
            completed < diff,
            "no edit payload is displayed before durable completion"
        );
        assert!(!stderr[..completed].contains("old\\u{009b}"));
        for control in [
            '\x1b', '\x07', '\u{009b}', '\u{202e}', '\u{200b}', '\u{2066}',
        ] {
            assert!(!stderr.contains(control));
        }
        let events = harness.events();
        let result = &events
            .iter()
            .find(|e| e["kind"] == "tool.completed")
            .unwrap()["data"];
        assert_eq!(result["is_error"], false);
        assert_eq!(
            result["output"]["new_sha256"],
            hex::encode(Sha256::digest(NEW.as_bytes()))
        );
        let requests = server.finish();
        let call = requests[1]["input"]
            .as_array()
            .unwrap()
            .iter()
            .find(|item| item["type"] == "function_call" && item["call_id"] == "edit-controls")
            .unwrap();
        assert_eq!(
            serde_json::from_str::<Value>(call["arguments"].as_str().unwrap()).unwrap(),
            arguments
        );
    }
}

#[test]
fn failed_edit_never_displays_an_applied_diff() {
    let harness = Harness::new();
    fs::write(harness.project.join("edit.txt"), "original").unwrap();
    let server = FakeProvider::new(vec![
        tool(
            "edit",
            json!({
                "path": "edit.txt", "old_text": "original", "new_text": "replacement",
                "expected_sha256": "0".repeat(64),
            }),
            "edit-fails",
        ),
        completed(vec![message("Not edited.")]),
    ]);
    let output = harness.run(&server, &["-p", "edit file"], None);
    assert!(output.status.success());
    assert_eq!(
        fs::read_to_string(harness.project.join("edit.txt")).unwrap(),
        "original"
    );
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("[tool:error] edit "));
    assert!(!stderr.contains("@@ exact replacement @@"));
    assert!(!stderr.contains("+replacement"));
    server.finish();
}

#[test]
fn large_edit_diff_is_bounded_without_truncating_the_actual_edit() {
    use sha2::{Digest, Sha256};
    let harness = Harness::new();
    fs::write(harness.project.join("edit.txt"), "old").unwrap();
    // The raw argument fits the display budget, but its safe representation
    // does not. The display-only cap must never trim the real replacement.
    let replacement = format!("{}ACTUAL_FILE_TAIL", "\u{202e}中".repeat(2500));
    let server = FakeProvider::new(vec![
        tool(
            "edit",
            json!({
                "path": "edit.txt", "old_text": "old", "new_text": replacement,
                "expected_sha256": hex::encode(Sha256::digest(b"old")),
            }),
            "large-edit",
        ),
        completed(vec![message("Edited.")]),
    ]);
    let output = harness.run(&server, &["-p", "edit file"], None);
    assert!(
        output.status.success(),
        "{:?}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        fs::read_to_string(harness.project.join("edit.txt")).unwrap(),
        replacement
    );
    let stderr = String::from_utf8(output.stderr).unwrap();
    let start = stderr.find("--- edit.txt\n").expect("production edit diff");
    let after_diff = &stderr[start..];
    let end = after_diff.find("...<truncated>\n").expect("bounded diff") + "...<truncated>".len();
    assert!(end <= 16 * 1024);
    assert!(!after_diff[..end].contains("ACTUAL_FILE_TAIL"));
    assert!(!stderr.contains('\u{202e}'));
    assert!(!stderr.contains('\x1b'));
    let requests = server.finish();
    let call = requests[1]["input"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["type"] == "function_call" && item["call_id"] == "large-edit")
        .unwrap();
    let replay: Value = serde_json::from_str(call["arguments"].as_str().unwrap()).unwrap();
    assert_eq!(replay["new_text"], replacement);
}
