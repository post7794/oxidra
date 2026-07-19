use std::collections::BTreeMap;
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const INITIAL_CALC: &str = "def add(a, b):\n    return a - b\n\nprint(add(3, 5))\n";
const FIXED_CALC: &str = "def add(a, b):\n    return a + b\n\nprint(add(3, 5))\n";
const FINAL_TEXT: &str = "Fixed calc.py; 3 + 5 now outputs 8.";
const READ_CALL_ID: &str = "call_read_calc";
const EDIT_CALL_ID: &str = "call_edit_calc";
const SHELL_CALL_ID: &str = "call_run_calc";

#[derive(Clone, Debug)]
struct CapturedRequest {
    method: String,
    target: String,
    headers: BTreeMap<String, String>,
    body: Value,
}

#[test]
fn cli_runs_read_edit_shell_and_replays_tool_outputs() {
    let Some(python) = find_python() else {
        eprintln!("skipping Oxidra CLI e2e test: python, python3, and py are unavailable");
        return;
    };

    let project = tempfile::tempdir().expect("create temporary project");
    let user_home = tempfile::tempdir().expect("create isolated user data directory");
    fs::write(project.path().join("calc.py"), INITIAL_CALC).expect("write initial calc.py");
    let initial_sha256 = sha256_hex(INITIAL_CALC.as_bytes());

    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind fake Responses server");
    let address = listener.local_addr().expect("read fake server address");
    let requests = Arc::new(Mutex::new(Vec::new()));
    let stop = Arc::new(AtomicBool::new(false));
    let server = {
        let requests = Arc::clone(&requests);
        let stop = Arc::clone(&stop);
        let python = python.clone();
        let initial_sha256 = initial_sha256.clone();
        thread::spawn(move || serve_responses(listener, requests, stop, &initial_sha256, &python))
    };

    let local_data = user_home.path().join("local");
    let roaming_data = user_home.path().join("roaming");
    let xdg_config = user_home.path().join("config");
    let xdg_state = user_home.path().join("state");
    for directory in [&local_data, &roaming_data, &xdg_config, &xdg_state] {
        fs::create_dir_all(directory).expect("create isolated user directory");
    }

    let output = Command::new(env!("CARGO_BIN_EXE_oxidra"))
        .arg("-p")
        .arg("Fix calc.py so 3+5 outputs 8, then run it to verify.")
        .arg("--full-auto")
        .arg("--cwd")
        .arg(project.path())
        .env("API_KEY", "fake")
        .env("API_BASE_URL", format!("http://{address}/v1/"))
        .env_remove("MODEL")
        .env_remove("OPENAI_API_KEY")
        .env_remove("OPENAI_BASE_URL")
        .env_remove("OPENAI_MODEL")
        .env("LOCALAPPDATA", &local_data)
        .env("APPDATA", &roaming_data)
        .env("XDG_CONFIG_HOME", &xdg_config)
        .env("XDG_STATE_HOME", &xdg_state)
        .env("HOME", user_home.path())
        .env("USERPROFILE", user_home.path())
        .env("NO_PROXY", "127.0.0.1,localhost")
        .env("no_proxy", "127.0.0.1,localhost")
        .output()
        .expect("run Oxidra CLI");

    stop.store(true, Ordering::Release);
    let server_result = server.join().expect("fake Responses server panicked");
    server_result.expect("fake Responses server failed");

    let stdout = String::from_utf8(output.stdout).expect("Oxidra stdout is UTF-8");
    let stderr = String::from_utf8(output.stderr).expect("Oxidra stderr is UTF-8");
    assert!(
        output.status.success(),
        "Oxidra exited with {}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        stdout,
        stderr
    );
    assert_eq!(stdout.replace("\r\n", "\n"), format!("{FINAL_TEXT}\n"));

    for tool in ["read", "edit", "shell"] {
        assert!(
            stderr.contains(&format!("[tool:start] {tool} ")),
            "missing start status for {tool}:\n{stderr}"
        );
        assert!(
            stderr.contains(&format!("[tool:ok] {tool} ")),
            "missing completion status for {tool}:\n{stderr}"
        );
    }
    assert!(
        stderr.contains("[tool] receiving arguments for call"),
        "streamed tool-call progress was not visible:\n{stderr}"
    );

    assert_eq!(
        fs::read_to_string(project.path().join("calc.py")).expect("read edited calc.py"),
        FIXED_CALC
    );
    let verification = Command::new(&python)
        .arg("calc.py")
        .current_dir(project.path())
        .output()
        .expect("run edited calc.py");
    assert!(
        verification.status.success(),
        "edited calc.py failed: {}",
        String::from_utf8_lossy(&verification.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&verification.stdout).trim(), "8");

    let requests = requests.lock().expect("lock captured requests").clone();
    assert_eq!(requests.len(), 4, "unexpected request count: {requests:#?}");
    for (index, request) in requests.iter().enumerate() {
        assert_eq!(request.method, "POST");
        assert_eq!(request.target, "/v1/responses");
        assert_eq!(
            request.headers.get("authorization").map(String::as_str),
            Some("Bearer fake")
        );
        assert_eq!(request.body["stream"].as_bool(), Some(true));
        assert_eq!(request.body["store"].as_bool(), Some(false));
        assert_eq!(request.body["model"], "gpt-5.6-sol");
        assert_eq!(
            function_outputs(&request.body).len(),
            index,
            "request {} did not replay every completed tool output",
            index + 1
        );
    }

    let read_output = function_output(&requests[1].body, READ_CALL_ID);
    assert_eq!(read_output["full_file_sha256"], initial_sha256);
    assert_eq!(read_output["text"], INITIAL_CALC);

    let expected_fixed_sha256 = sha256_hex(FIXED_CALC.as_bytes());
    let edit_output = function_output(&requests[2].body, EDIT_CALL_ID);
    assert_eq!(edit_output["new_sha256"], expected_fixed_sha256);
    assert_eq!(edit_output["replaced_count"], 1);

    let shell_output = function_output(&requests[3].body, SHELL_CALL_ID);
    assert_eq!(shell_output["exit_code"], 0);
    assert_eq!(
        shell_output["stdout"]
            .as_str()
            .expect("shell stdout is a string")
            .trim(),
        "8"
    );
}

#[test]
fn interactive_text_delta_is_visible_before_response_completed() {
    const STREAMED: &str = "streamed before completion";

    let project = tempfile::tempdir().expect("create temporary project");
    let user_home = tempfile::tempdir().expect("create isolated user data directory");
    let local_data = user_home.path().join("local");
    let roaming_data = user_home.path().join("roaming");
    let xdg_config = user_home.path().join("config");
    let xdg_state = user_home.path().join("state");
    for directory in [&local_data, &roaming_data, &xdg_config, &xdg_state] {
        fs::create_dir_all(directory).expect("create isolated user directory");
    }

    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind streaming server");
    let address = listener
        .local_addr()
        .expect("read streaming server address");
    let (delta_sent, delta_ready) = mpsc::channel();
    let (finish_response, finish_allowed) = mpsc::channel();
    let server = thread::spawn(move || -> Result<(), String> {
        let (mut stream, _) = listener.accept().map_err(|error| error.to_string())?;
        let _request = read_http_request(&mut stream)?;
        let (first, rest) = split_text_sse("resp_stream", STREAMED);
        let content_length = first.len() + rest.len();
        write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {content_length}\r\nConnection: close\r\n\r\n"
        )
        .map_err(|error| error.to_string())?;
        stream
            .write_all(first.as_bytes())
            .map_err(|error| error.to_string())?;
        stream.flush().map_err(|error| error.to_string())?;
        delta_sent.send(()).map_err(|error| error.to_string())?;
        finish_allowed
            .recv_timeout(Duration::from_secs(5))
            .map_err(|error| error.to_string())?;
        stream
            .write_all(rest.as_bytes())
            .map_err(|error| error.to_string())?;
        stream.flush().map_err(|error| error.to_string())?;
        Ok(())
    });

    let mut child = Command::new(env!("CARGO_BIN_EXE_oxidra"))
        .arg("--cwd")
        .arg(project.path())
        .env("API_KEY", "fake")
        .env("API_BASE_URL", format!("http://{address}/v1/"))
        .env_remove("MODEL")
        .env_remove("OPENAI_API_KEY")
        .env_remove("OPENAI_BASE_URL")
        .env_remove("OPENAI_MODEL")
        .env("LOCALAPPDATA", &local_data)
        .env("APPDATA", &roaming_data)
        .env("XDG_CONFIG_HOME", &xdg_config)
        .env("XDG_STATE_HOME", &xdg_state)
        .env("HOME", user_home.path())
        .env("USERPROFILE", user_home.path())
        .env("NO_PROXY", "127.0.0.1,localhost")
        .env("no_proxy", "127.0.0.1,localhost")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn interactive Oxidra");
    let mut stdin = child.stdin.take().expect("capture child stdin");
    let mut stdout = child.stdout.take().expect("capture child stdout");
    let (observed, observed_rx) = mpsc::channel();
    let stdout_reader = thread::spawn(move || {
        let mut output = Vec::new();
        let mut buffer = [0u8; 256];
        let mut announced = false;
        loop {
            let read = stdout.read(&mut buffer).expect("read streamed stdout");
            if read == 0 {
                break;
            }
            output.extend_from_slice(&buffer[..read]);
            if !announced && find_bytes(&output, STREAMED.as_bytes()).is_some() {
                observed.send(()).expect("announce streamed delta");
                announced = true;
            }
        }
        output
    });

    stdin
        .write_all(b"give one short answer\n")
        .expect("write interactive prompt");
    stdin.flush().expect("flush interactive prompt");
    delta_ready
        .recv_timeout(Duration::from_secs(5))
        .expect("server did not send delta");
    observed_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("text delta was not visible before response.completed");
    finish_response.send(()).expect("allow response completion");
    stdin.write_all(b"exit\n").expect("write REPL exit");
    drop(stdin);

    let status = wait_child_bounded(&mut child, Duration::from_secs(10));
    assert!(status.success(), "interactive Oxidra exited with {status}");
    let output = stdout_reader.join().expect("stdout reader panicked");
    assert!(
        find_bytes(&output, STREAMED.as_bytes()).is_some(),
        "streamed text was absent from stdout: {}",
        String::from_utf8_lossy(&output)
    );
    server
        .join()
        .expect("streaming server panicked")
        .expect("streaming server failed");
}

#[test]
fn resume_replays_complete_output_items_across_processes() {
    let project = tempfile::tempdir().expect("create temporary project");
    let user_home = tempfile::tempdir().expect("create isolated user data directory");
    let local_data = user_home.path().join("local");
    let roaming_data = user_home.path().join("roaming");
    let xdg_config = user_home.path().join("config");
    let xdg_state = user_home.path().join("state");
    for directory in [&local_data, &roaming_data, &xdg_config, &xdg_state] {
        fs::create_dir_all(directory).expect("create isolated user directory");
    }

    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind resume server");
    let address = listener.local_addr().expect("read resume server address");
    let captured = Arc::new(Mutex::new(Vec::new()));
    let server = {
        let captured = Arc::clone(&captured);
        thread::spawn(move || -> Result<(), String> {
            for body in [
                resume_first_sse(),
                final_text_sse("resp_resume_2", "second done"),
            ] {
                let (mut stream, _) = listener.accept().map_err(|error| error.to_string())?;
                let request = read_http_request(&mut stream)?;
                captured
                    .lock()
                    .map_err(|_| "resume request lock poisoned".to_owned())?
                    .push(request);
                write_http_response(&mut stream, "200 OK", "text/event-stream", &body)?;
            }
            Ok(())
        })
    };

    let run = |prompt: &str, resume: Option<&str>| {
        let mut command = Command::new(env!("CARGO_BIN_EXE_oxidra"));
        command
            .arg("-p")
            .arg(prompt)
            .arg("--cwd")
            .arg(project.path())
            .env("API_KEY", "fake")
            .env("API_BASE_URL", format!("http://{address}/v1/"))
            .env_remove("MODEL")
            .env_remove("OPENAI_API_KEY")
            .env_remove("OPENAI_BASE_URL")
            .env_remove("OPENAI_MODEL")
            .env("LOCALAPPDATA", &local_data)
            .env("APPDATA", &roaming_data)
            .env("XDG_CONFIG_HOME", &xdg_config)
            .env("XDG_STATE_HOME", &xdg_state)
            .env("HOME", user_home.path())
            .env("USERPROFILE", user_home.path())
            .env("NO_PROXY", "127.0.0.1,localhost")
            .env("no_proxy", "127.0.0.1,localhost");
        if let Some(session_id) = resume {
            command.arg("--resume").arg(session_id);
        }
        command.output().expect("run resumable Oxidra process")
    };

    let first = run("first prompt", None);
    assert!(
        first.status.success(),
        "first process failed: {}",
        String::from_utf8_lossy(&first.stderr)
    );
    let first_stderr = String::from_utf8(first.stderr).expect("first stderr is UTF-8");
    let session_id = first_stderr
        .lines()
        .find_map(|line| line.strip_prefix("Oxidra session "))
        .and_then(|line| line.split_once(" (root:").map(|(id, _)| id.to_owned()))
        .unwrap_or_else(|| panic!("missing session id in stderr:\n{first_stderr}"));

    let second = run("second prompt", Some(&session_id));
    assert!(
        second.status.success(),
        "resumed process failed: {}",
        String::from_utf8_lossy(&second.stderr)
    );
    server
        .join()
        .expect("resume server panicked")
        .expect("resume server failed");

    let captured = captured.lock().expect("lock resume requests");
    assert_eq!(captured.len(), 2);
    let input = captured[1].body["input"]
        .as_array()
        .expect("resumed request input is an array");
    assert!(
        input
            .iter()
            .any(|item| { item["role"] == "user" && item["content"] == "first prompt" })
    );
    assert!(input.iter().any(|item| {
        item["type"] == "reasoning"
            && item["encrypted_content"] == "encrypted-fixture"
            && item["phase"] == "analysis"
    }));
    assert!(
        input
            .iter()
            .any(|item| { item["role"] == "user" && item["content"] == "second prompt" })
    );
}

fn find_python() -> Option<String> {
    ["python", "python3", "py"].into_iter().find_map(|name| {
        let status = Command::new(name)
            .arg("--version")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .ok()?;
        status.success().then(|| name.to_owned())
    })
}

fn serve_responses(
    listener: TcpListener,
    requests: Arc<Mutex<Vec<CapturedRequest>>>,
    stop: Arc<AtomicBool>,
    initial_sha256: &str,
    python: &str,
) -> Result<(), String> {
    listener
        .set_nonblocking(true)
        .map_err(|error| format!("set listener nonblocking: {error}"))?;

    while !stop.load(Ordering::Acquire) {
        let (mut stream, _) = match listener.accept() {
            Ok(connection) => connection,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(10));
                continue;
            }
            Err(error) => return Err(format!("accept request: {error}")),
        };
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .map_err(|error| format!("set request timeout: {error}"))?;

        let request = read_http_request(&mut stream)?;
        let request_index = {
            let mut captured = requests
                .lock()
                .map_err(|_| "captured request mutex was poisoned".to_owned())?;
            let index = captured.len();
            captured.push(request);
            index
        };

        let body = match request_index {
            0 => tool_call_sse(
                "resp_read",
                "item_read",
                READ_CALL_ID,
                "read",
                json!({"path": "calc.py"}),
            ),
            1 => tool_call_sse(
                "resp_edit",
                "item_edit",
                EDIT_CALL_ID,
                "edit",
                json!({
                    "path": "calc.py",
                    "old_text": "a - b",
                    "new_text": "a + b",
                    "expected_sha256": initial_sha256,
                }),
            ),
            2 => tool_call_sse(
                "resp_shell",
                "item_shell",
                SHELL_CALL_ID,
                "shell",
                json!({"command": format!("{python} calc.py")}),
            ),
            3 => final_text_sse("resp_final", FINAL_TEXT),
            _ => {
                return Err(format!(
                    "unexpected Responses request {}",
                    request_index + 1
                ));
            }
        };
        write_http_response(&mut stream, "200 OK", "text/event-stream", &body)?;

        if request_index == 3 {
            return Ok(());
        }
    }
    Ok(())
}

fn read_http_request(stream: &mut TcpStream) -> Result<CapturedRequest, String> {
    let mut bytes = Vec::new();
    let header_end = loop {
        if let Some(index) = find_bytes(&bytes, b"\r\n\r\n") {
            break index;
        }
        let mut buffer = [0_u8; 8 * 1024];
        let count = stream
            .read(&mut buffer)
            .map_err(|error| format!("read request headers: {error}"))?;
        if count == 0 {
            return Err("connection closed before request headers completed".to_owned());
        }
        bytes.extend_from_slice(&buffer[..count]);
        if bytes.len() > 128 * 1024 {
            return Err("request headers exceeded 128 KiB".to_owned());
        }
    };

    let headers_text = std::str::from_utf8(&bytes[..header_end])
        .map_err(|error| format!("request headers were not UTF-8: {error}"))?;
    let mut lines = headers_text.split("\r\n");
    let request_line = lines
        .next()
        .ok_or_else(|| "missing HTTP request line".to_owned())?;
    let mut request_parts = request_line.split_whitespace();
    let method = request_parts
        .next()
        .ok_or_else(|| "missing HTTP method".to_owned())?
        .to_owned();
    let target = request_parts
        .next()
        .ok_or_else(|| "missing HTTP target".to_owned())?
        .to_owned();

    let mut headers = BTreeMap::new();
    for line in lines {
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| format!("invalid HTTP header: {line:?}"))?;
        headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_owned());
    }
    let content_length = headers
        .get("content-length")
        .ok_or_else(|| "request omitted Content-Length".to_owned())?
        .parse::<usize>()
        .map_err(|error| format!("invalid Content-Length: {error}"))?;

    let body_start = header_end + 4;
    while bytes.len() < body_start + content_length {
        let mut buffer = [0_u8; 8 * 1024];
        let count = stream
            .read(&mut buffer)
            .map_err(|error| format!("read request body: {error}"))?;
        if count == 0 {
            return Err("connection closed before request body completed".to_owned());
        }
        bytes.extend_from_slice(&buffer[..count]);
    }
    let body = serde_json::from_slice(&bytes[body_start..body_start + content_length])
        .map_err(|error| format!("parse request JSON: {error}"))?;

    Ok(CapturedRequest {
        method,
        target,
        headers,
        body,
    })
}

fn write_http_response(
    stream: &mut TcpStream,
    status: &str,
    content_type: &str,
    body: &str,
) -> Result<(), String> {
    let headers = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nCache-Control: no-cache\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream
        .write_all(headers.as_bytes())
        .and_then(|()| stream.write_all(body.as_bytes()))
        .and_then(|()| stream.flush())
        .map_err(|error| format!("write HTTP response: {error}"))
}

fn tool_call_sse(
    response_id: &str,
    item_id: &str,
    call_id: &str,
    name: &str,
    arguments: Value,
) -> String {
    let arguments = serde_json::to_string(&arguments).expect("serialize tool arguments");
    let item = json!({
        "type": "function_call",
        "id": item_id,
        "call_id": call_id,
        "name": name,
        "status": "completed",
    });
    let mut body = String::new();
    push_sse(
        &mut body,
        "response.created",
        json!({"type": "response.created", "response": {"id": response_id}}),
    );
    push_sse(
        &mut body,
        "response.output_item.added",
        json!({
            "type": "response.output_item.added",
            "output_index": 0,
            "item": item,
        }),
    );
    push_sse(
        &mut body,
        "response.function_call_arguments.delta",
        json!({
            "type": "response.function_call_arguments.delta",
            "output_index": 0,
            "item_id": item_id,
            "call_id": call_id,
            "delta": arguments,
        }),
    );
    push_sse(
        &mut body,
        "response.function_call_arguments.done",
        json!({
            "type": "response.function_call_arguments.done",
            "output_index": 0,
            "item_id": item_id,
            "call_id": call_id,
            "arguments": arguments,
        }),
    );
    push_sse(
        &mut body,
        "response.output_item.done",
        json!({
            "type": "response.output_item.done",
            "output_index": 0,
            "item": item,
        }),
    );
    push_sse(
        &mut body,
        "response.completed",
        json!({
            "type": "response.completed",
            "response": completed_response(response_id, vec![item]),
        }),
    );
    body
}

fn final_text_sse(response_id: &str, text: &str) -> String {
    let item = json!({
        "type": "message",
        "id": "message_final",
        "role": "assistant",
        "status": "completed",
        "content": [{"type": "output_text", "text": text, "annotations": []}],
    });
    let mut body = String::new();
    push_sse(
        &mut body,
        "response.created",
        json!({"type": "response.created", "response": {"id": response_id}}),
    );
    push_sse(
        &mut body,
        "response.output_text.delta",
        json!({
            "type": "response.output_text.delta",
            "output_index": 0,
            "content_index": 0,
            "delta": text,
        }),
    );
    push_sse(
        &mut body,
        "response.output_item.done",
        json!({
            "type": "response.output_item.done",
            "output_index": 0,
            "item": item,
        }),
    );
    push_sse(
        &mut body,
        "response.completed",
        json!({
            "type": "response.completed",
            "response": completed_response(response_id, vec![item]),
        }),
    );
    body
}

fn resume_first_sse() -> String {
    let reasoning = json!({
        "type": "reasoning",
        "id": "reasoning_resume",
        "encrypted_content": "encrypted-fixture",
        "summary": [],
        "phase": "analysis",
    });
    let message = json!({
        "type": "message",
        "id": "message_resume",
        "role": "assistant",
        "status": "completed",
        "content": [{"type": "output_text", "text": "first done", "annotations": []}],
    });
    let mut body = String::new();
    push_sse(
        &mut body,
        "response.created",
        json!({"type": "response.created", "response": {"id": "resp_resume_1"}}),
    );
    push_sse(
        &mut body,
        "response.output_item.done",
        json!({
            "type": "response.output_item.done",
            "output_index": 0,
            "item": reasoning,
        }),
    );
    push_sse(
        &mut body,
        "response.output_text.delta",
        json!({
            "type": "response.output_text.delta",
            "output_index": 1,
            "content_index": 0,
            "delta": "first done",
        }),
    );
    push_sse(
        &mut body,
        "response.output_item.done",
        json!({
            "type": "response.output_item.done",
            "output_index": 1,
            "item": message,
        }),
    );
    push_sse(
        &mut body,
        "response.completed",
        json!({
            "type": "response.completed",
            "response": completed_response("resp_resume_1", vec![reasoning, message]),
        }),
    );
    body
}

fn split_text_sse(response_id: &str, text: &str) -> (String, String) {
    let item = json!({
        "type": "message",
        "id": "message_streamed",
        "role": "assistant",
        "status": "completed",
        "content": [{"type": "output_text", "text": text, "annotations": []}],
    });
    let mut first = String::new();
    push_sse(
        &mut first,
        "response.created",
        json!({"type": "response.created", "response": {"id": response_id}}),
    );
    push_sse(
        &mut first,
        "response.output_text.delta",
        json!({
            "type": "response.output_text.delta",
            "output_index": 0,
            "content_index": 0,
            "delta": text,
        }),
    );

    let mut rest = String::new();
    push_sse(
        &mut rest,
        "response.output_item.done",
        json!({
            "type": "response.output_item.done",
            "output_index": 0,
            "item": item,
        }),
    );
    push_sse(
        &mut rest,
        "response.completed",
        json!({
            "type": "response.completed",
            "response": completed_response(response_id, vec![item]),
        }),
    );
    (first, rest)
}

fn completed_response(response_id: &str, output: Vec<Value>) -> Value {
    json!({
        "id": response_id,
        "object": "response",
        "status": "completed",
        "output": output,
        "usage": {
            "input_tokens": 1,
            "input_tokens_details": {"cached_tokens": 0},
            "output_tokens": 1,
            "output_tokens_details": {"reasoning_tokens": 0},
            "total_tokens": 2,
        },
    })
}

fn push_sse(body: &mut String, event: &str, payload: Value) {
    body.push_str("event: ");
    body.push_str(event);
    body.push('\n');
    body.push_str("data: ");
    body.push_str(&serde_json::to_string(&payload).expect("serialize SSE payload"));
    body.push_str("\n\n");
}

fn function_outputs(body: &Value) -> Vec<&Value> {
    body["input"]
        .as_array()
        .expect("Responses input is an array")
        .iter()
        .filter(|item| item["type"] == "function_call_output")
        .collect()
}

fn function_output(body: &Value, call_id: &str) -> Value {
    let item = function_outputs(body)
        .into_iter()
        .find(|item| item["call_id"] == call_id)
        .unwrap_or_else(|| panic!("missing function_call_output for {call_id}: {body:#}"));
    serde_json::from_str(
        item["output"]
            .as_str()
            .expect("function_call_output output is a JSON string"),
    )
    .expect("parse function_call_output JSON")
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn wait_child_bounded(
    child: &mut std::process::Child,
    duration: Duration,
) -> std::process::ExitStatus {
    let deadline = Instant::now() + duration;
    loop {
        if let Some(status) = child.try_wait().expect("poll child status") {
            return status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            return child.wait().expect("wait for killed child");
        }
        thread::sleep(Duration::from_millis(20));
    }
}
