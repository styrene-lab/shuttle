use crate::client::SshClient;
use crate::config::ShuttleConfig;
use rand_core::RngCore;
use serde_json::{json, Value};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;

const ALLOWED_INTERPRETERS: &[&str] = &[
    "/bin/bash",
    "/bin/sh",
    "/usr/bin/bash",
    "/usr/bin/sh",
    "/usr/bin/python3",
    "/usr/bin/python",
    "/usr/bin/perl",
    "/usr/bin/ruby",
];

/// Execute a single command on a remote host.
pub async fn ssh_exec(
    client: &Arc<Mutex<SshClient>>,
    config: &ShuttleConfig,
    params: &Value,
) -> omegon_extension::Result<Value> {
    let command = params
        .get("command")
        .and_then(|v| v.as_str())
        .ok_or_else(|| omegon_extension::Error::invalid_params("missing 'command'"))?;

    let timeout_secs = params
        .get("timeout_secs")
        .and_then(|v| v.as_u64())
        .unwrap_or(config.default_timeout_secs)
        .min(3600);

    let client = client.lock().await;
    let result = client
        .exec(
            command,
            Duration::from_secs(timeout_secs),
            config.max_output_bytes,
        )
        .await
        .map_err(|e| omegon_extension::Error::internal_error(e.to_string()))?;

    let stdout = String::from_utf8_lossy(&result.stdout);
    let stderr = String::from_utf8_lossy(&result.stderr);

    Ok(json!({
        "host": client.host_name(),
        "exit_code": result.exit_code,
        "stdout": stdout,
        "stderr": stderr,
        "truncated": result.truncated,
    }))
}

/// Upload and execute a multi-line script on a remote host.
///
/// The script is piped through a random-delimited heredoc to the interpreter.
/// The delimiter is generated per-invocation to prevent injection.
pub async fn ssh_script(
    client: &Arc<Mutex<SshClient>>,
    config: &ShuttleConfig,
    params: &Value,
) -> omegon_extension::Result<Value> {
    let script = params
        .get("script")
        .and_then(|v| v.as_str())
        .ok_or_else(|| omegon_extension::Error::invalid_params("missing 'script'"))?;

    let interpreter = params
        .get("interpreter")
        .and_then(|v| v.as_str())
        .unwrap_or("/bin/bash");

    if !ALLOWED_INTERPRETERS.contains(&interpreter) {
        return Err(omegon_extension::Error::invalid_params(format!(
            "interpreter not allowed: {interpreter}. Allowed: {}",
            ALLOWED_INTERPRETERS.join(", ")
        )));
    }

    let timeout_secs = params
        .get("timeout_secs")
        .and_then(|v| v.as_u64())
        .unwrap_or(config.default_timeout_secs)
        .min(3600);

    // Generate a random delimiter that does not appear as a standalone
    // line in the script body. A delimiter collision would terminate the
    // quoted heredoc early and let trailing script bytes execute as shell.
    let delimiter = loop {
        let candidate = format!(
            "SHUTTLE_EOF_{:016x}{:016x}",
            rand_core::OsRng.next_u64(),
            rand_core::OsRng.next_u64()
        );
        if !script.lines().any(|line| line == candidate) {
            break candidate;
        }
    };

    let wrapped = format!("{interpreter} -s <<'{delimiter}'\n{script}\n{delimiter}");

    let client = client.lock().await;
    let result = client
        .exec(
            &wrapped,
            Duration::from_secs(timeout_secs),
            config.max_output_bytes,
        )
        .await
        .map_err(|e| omegon_extension::Error::internal_error(e.to_string()))?;

    let stdout = String::from_utf8_lossy(&result.stdout);
    let stderr = String::from_utf8_lossy(&result.stderr);

    Ok(json!({
        "host": client.host_name(),
        "exit_code": result.exit_code,
        "stdout": stdout,
        "stderr": stderr,
        "truncated": result.truncated,
    }))
}
