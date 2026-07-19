//! Live SSH integration tests.
//!
//! Require a running sshd container. Set up with:
//!   ./test-infra/setup.sh
//!   source /tmp/shuttle-test-*/test.env
//!
//! These tests send JSON-RPC messages to the shuttle binary over stdin/stdout.
//! They exercise the full stack: config → auth → russh → sshd → command.

use serde_json::{json, Value};
use std::io::{BufRead, Write};
use std::process::{Command, Stdio};

fn shuttle_binary() -> String {
    let dir = env!("CARGO_MANIFEST_DIR");
    format!("{dir}/target/release/shuttle")
}

fn required_env(var: &str) -> String {
    std::env::var(var).unwrap_or_else(|_| {
        panic!("required integration environment variable {var} is missing; run test-infra/run.sh")
    })
}

struct RpcHarness {
    child: std::process::Child,
    stdin: std::process::ChildStdin,
    reader: std::io::BufReader<std::process::ChildStdout>,
    next_id: u64,
}

impl RpcHarness {
    fn start() -> Self {
        let binary = shuttle_binary();
        let hosts_file = required_env("SHUTTLE_HOSTS_FILE");
        let known_hosts = required_env("SHUTTLE_KNOWN_HOSTS");
        let test_dir = required_env("SHUTTLE_TEST_DIR");

        let mut child = Command::new(&binary)
            .arg("--rpc")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .env("STYRENE_PASSPHRASE", "shuttle-test-passphrase")
            .spawn()
            .unwrap_or_else(|e| panic!("failed to start {binary}: {e}"));

        let stdin = child.stdin.take().unwrap();
        let stdout = child.stdout.take().unwrap();
        let reader = std::io::BufReader::new(stdout);

        let mut harness = Self {
            child,
            stdin,
            reader,
            next_id: 1,
        };

        // Initialize
        let init_result = harness.call("initialize", json!({}));
        assert_eq!(init_result["protocol_version"], 2);

        // Bootstrap config
        harness.call(
            "bootstrap_config",
            json!({
                "hosts_file": hosts_file,
                "known_hosts_file": known_hosts,
                "allowed_hosts": "test-local",
                "allowed_local_roots": test_dir,
                "default_timeout_secs": 10,
            }),
        );

        harness
    }

    fn call(&mut self, method: &str, params: Value) -> Value {
        let id = format!("test-{}", self.next_id);
        self.next_id += 1;

        let request = json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
            "params": params,
        });

        let mut line = serde_json::to_string(&request).unwrap();
        line.push('\n');
        self.stdin.write_all(line.as_bytes()).unwrap();
        self.stdin.flush().unwrap();

        let mut response_line = String::new();
        self.reader.read_line(&mut response_line).unwrap();

        let response: Value = serde_json::from_str(&response_line)
            .unwrap_or_else(|e| panic!("bad JSON response: {e}\nraw: {response_line}"));

        if let Some(error) = response.get("error") {
            panic!("RPC error on {method}: {error}");
        }

        response["result"].clone()
    }

    fn call_tool(&mut self, name: &str, args: Value) -> Value {
        self.call(
            "tools/call",
            json!({
                "name": name,
                "arguments": args,
            }),
        )
    }

    fn call_tool_expect_error(&mut self, name: &str, args: Value) -> Value {
        let id = format!("test-{}", self.next_id);
        self.next_id += 1;

        let request = json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "tools/call",
            "params": {
                "name": name,
                "arguments": args,
            },
        });

        let mut line = serde_json::to_string(&request).unwrap();
        line.push('\n');
        self.stdin.write_all(line.as_bytes()).unwrap();
        self.stdin.flush().unwrap();

        let mut response_line = String::new();
        self.reader.read_line(&mut response_line).unwrap();

        let response: Value = serde_json::from_str(&response_line).unwrap();
        assert!(
            response.get("error").is_some(),
            "expected error for {name}, got success"
        );
        response["error"].clone()
    }
}

impl Drop for RpcHarness {
    fn drop(&mut self) {
        let _ = self.child.kill();
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────
// Note: these tests are sequential because they share one shuttle process.
// Run with: cargo test --test integration -- --test-threads=1

#[test]
fn test_ssh_hosts() {
    let mut h = RpcHarness::start();
    let result = h.call_tool("ssh_hosts", json!({}));
    let hosts = result["hosts"].as_array().unwrap();
    assert_eq!(hosts.len(), 1);
    assert_eq!(hosts[0]["name"], "test-local");
    assert_eq!(hosts[0]["user"], "root");
    // identity_label should NOT be exposed
    assert!(hosts[0].get("identity_label").is_none());
}

#[test]
fn test_ssh_ping() {
    let mut h = RpcHarness::start();
    let result = h.call_tool("ssh_ping", json!({"host": "test-local"}));
    assert_eq!(result["reachable"], true);
    assert!(result["latency_ms"].as_u64().unwrap() < 5000);
}

#[test]
fn test_ssh_exec_basic() {
    let mut h = RpcHarness::start();
    let result = h.call_tool(
        "ssh_exec",
        json!({"host": "test-local", "command": "echo hello-shuttle"}),
    );
    assert_eq!(result["exit_code"], 0);
    assert!(result["stdout"].as_str().unwrap().contains("hello-shuttle"));
}

#[test]
fn test_ssh_exec_exit_code() {
    let mut h = RpcHarness::start();
    let result = h.call_tool(
        "ssh_exec",
        json!({"host": "test-local", "command": "sh -c 'exit 42'"}),
    );
    assert_eq!(result["exit_code"], 42);
}

#[test]
fn test_ssh_exec_stderr() {
    let mut h = RpcHarness::start();
    let result = h.call_tool(
        "ssh_exec",
        json!({"host": "test-local", "command": "echo err >&2"}),
    );
    assert!(result["stderr"].as_str().unwrap().contains("err"));
}

#[test]
fn test_ssh_script() {
    let mut h = RpcHarness::start();
    let result = h.call_tool(
        "ssh_script",
        json!({
            "host": "test-local",
            "script": "x=42\necho \"value=$x\""
        }),
    );
    assert_eq!(result["exit_code"], 0);
    assert!(result["stdout"].as_str().unwrap().contains("value=42"));
}

#[test]
fn test_ssh_script_bad_interpreter() {
    let mut h = RpcHarness::start();
    let err = h.call_tool_expect_error(
        "ssh_script",
        json!({
            "host": "test-local",
            "script": "echo hi",
            "interpreter": "/usr/bin/env"
        }),
    );
    assert!(err["message"].as_str().unwrap().contains("not allowed"));
}

#[test]
fn test_sftp_ls() {
    let mut h = RpcHarness::start();
    let result = h.call_tool(
        "sftp_ls",
        json!({"host": "test-local", "path": "/tmp/test-dir"}),
    );
    let entries = result["entries"].as_array().unwrap();
    let names: Vec<&str> = entries
        .iter()
        .map(|e| e["name"].as_str().unwrap())
        .collect();
    assert!(names.contains(&"a.txt"));
    assert!(names.contains(&"b.txt"));
}

#[test]
fn test_sftp_read() {
    let mut h = RpcHarness::start();
    let result = h.call_tool(
        "sftp_read",
        json!({"host": "test-local", "path": "/tmp/test-file.txt"}),
    );
    assert!(result["content"]
        .as_str()
        .unwrap()
        .contains("hello from shuttle"));
}

#[test]
fn test_scp_push_rejects_file_outside_allowed_root() {
    let mut h = RpcHarness::start();
    let outside = std::env::temp_dir().join("shuttle-outside-root.txt");
    std::fs::write(&outside, "blocked").unwrap();
    let err = h.call_tool_expect_error(
        "scp_push",
        json!({
            "host": "test-local",
            "local_path": outside,
            "remote_path": "/tmp/should-not-upload.txt",
        }),
    );
    assert!(err["message"]
        .as_str()
        .unwrap()
        .contains("outside allowed_local_roots"));
    let _ = std::fs::remove_file(outside);
}

#[test]
fn test_scp_push_pull_roundtrip() {
    let mut h = RpcHarness::start();
    let test_dir = std::env::var("SHUTTLE_TEST_DIR").unwrap();
    let local_src = format!("{test_dir}/push-test.txt");
    let local_dst = format!("{test_dir}/pull-test.txt");
    let remote_path = "/tmp/shuttle-roundtrip.txt";

    std::fs::write(&local_src, "roundtrip-payload-42").unwrap();

    let push_result = h.call_tool(
        "scp_push",
        json!({
            "host": "test-local",
            "local_path": local_src,
            "remote_path": remote_path,
        }),
    );
    assert_eq!(push_result["bytes_written"], 20);

    let pull_result = h.call_tool(
        "scp_pull",
        json!({
            "host": "test-local",
            "remote_path": remote_path,
            "local_path": local_dst,
        }),
    );
    assert_eq!(pull_result["bytes_written"], 20);

    let content = std::fs::read_to_string(&local_dst).unwrap();
    assert_eq!(content, "roundtrip-payload-42");
}

#[test]
fn test_tunnel_open_close_lifecycle() {
    let mut h = RpcHarness::start();

    let open_result = h.call_tool(
        "ssh_tunnel_open",
        json!({
            "host": "test-local",
            "local_port": 19876,
            "remote_host": "127.0.0.1",
            "remote_port": 22,
        }),
    );
    let tunnel_id = open_result["tunnel_id"].as_str().unwrap().to_string();
    assert!(tunnel_id.starts_with("tun-"));
    assert_eq!(open_result["local_port"], 19876);

    let list_result = h.call_tool("ssh_tunnel_list", json!({}));
    let tunnels = list_result["tunnels"].as_array().unwrap();
    assert_eq!(tunnels.len(), 1);
    assert_eq!(tunnels[0]["tunnel_id"].as_str().unwrap(), tunnel_id);

    let close_result = h.call_tool("ssh_tunnel_close", json!({"tunnel_id": tunnel_id}));
    assert_eq!(close_result["closed"], true);

    let list_after = h.call_tool("ssh_tunnel_list", json!({}));
    assert_eq!(list_after["tunnels"].as_array().unwrap().len(), 0);
}

#[test]
fn test_ssh_migrate_analyze() {
    let mut h = RpcHarness::start();
    let result = h.call_tool("ssh_migrate_analyze", json!({}));
    assert!(result["ssh_dir_exists"].is_boolean());
    if result["ssh_dir_exists"] == false {
        assert!(result["summary"].is_string());
        return;
    }
    assert!(result["key_files"].is_array());
    assert!(result["ssh_config_hosts"].is_array());
    assert!(result["draft_hosts_toml"].is_string());
    assert!(result["keygen_commands"].is_array());
    assert!(result["migration_steps"].is_array());
}

#[test]
fn test_disallowed_host() {
    let mut h = RpcHarness::start();
    let err = h.call_tool_expect_error(
        "ssh_exec",
        json!({"host": "not-configured", "command": "echo hi"}),
    );
    assert!(
        err["message"]
            .as_str()
            .unwrap()
            .contains("not in allowlist")
            || err["message"].as_str().unwrap().contains("not found")
    );
}

#[test]
fn test_tunnel_non_loopback_blocked() {
    let mut h = RpcHarness::start();
    let err = h.call_tool_expect_error(
        "ssh_tunnel_open",
        json!({
            "host": "test-local",
            "local_port": 19999,
            "remote_host": "10.0.0.1",
            "remote_port": 80
        }),
    );
    assert!(err["message"]
        .as_str()
        .unwrap()
        .contains("allowed_tunnel_destinations"));
}

#[test]
fn test_tunnel_zero_bypass_blocked() {
    let mut h = RpcHarness::start();
    let err = h.call_tool_expect_error(
        "ssh_tunnel_open",
        json!({
            "host": "test-local",
            "local_port": 19998,
            "remote_host": "0.0.0.0",
            "remote_port": 80
        }),
    );
    assert!(err["message"]
        .as_str()
        .unwrap()
        .contains("allowed_tunnel_destinations"));
}

#[test]
fn test_tunnel_privileged_port_blocked() {
    let mut h = RpcHarness::start();
    let err = h.call_tool_expect_error(
        "ssh_tunnel_open",
        json!({
            "host": "test-local",
            "local_port": 80,
            "remote_host": "127.0.0.1",
            "remote_port": 8080
        }),
    );
    assert!(err["message"].as_str().unwrap().contains("1024"));
}

#[test]
fn test_port_overflow_rejected() {
    let mut h = RpcHarness::start();
    let err = h.call_tool_expect_error(
        "ssh_tunnel_open",
        json!({
            "host": "test-local",
            "local_port": 70000,
            "remote_host": "127.0.0.1",
            "remote_port": 80
        }),
    );
    assert!(err["message"].as_str().unwrap().contains("65535"));
}

#[test]
fn test_local_path_etc_blocked() {
    let mut h = RpcHarness::start();
    let err = h.call_tool_expect_error(
        "scp_push",
        json!({
            "host": "test-local",
            "local_path": "/etc/passwd",
            "remote_path": "/tmp/exfil"
        }),
    );
    assert!(err["message"]
        .as_str()
        .unwrap()
        .contains("outside allowed_local_roots"));
}

#[test]
fn test_local_path_ssh_blocked() {
    let mut h = RpcHarness::start();
    let ssh_path = dirs::home_dir().unwrap().join(".ssh/id_rsa");
    let err = h.call_tool_expect_error(
        "scp_push",
        json!({
            "host": "test-local",
            "local_path": ssh_path.to_str().unwrap(),
            "remote_path": "/tmp/exfil"
        }),
    );
    let message = err["message"].as_str().unwrap();
    assert!(
        message.contains("outside allowed_local_roots")
            || message.contains("cannot resolve local path")
            || message.contains("local path does not exist")
            || message.contains("invalid path: parent dir not found")
    );
}
