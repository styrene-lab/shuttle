use serde_json::{json, Value};

pub fn tool_definitions() -> Vec<Value> {
    vec![
        json!({
            "name": "ssh_exec",
            "label": "SSH Execute",
            "description": "Run a command on a remote host. Returns stdout, stderr, and exit code.",
            "parameters": {
                "type": "object",
                "properties": {
                    "host": {
                        "type": "string",
                        "description": "Host name as defined in hosts.toml."
                    },
                    "auth": {
                        "type": "string",
                        "description": "Optional exact authentication profile name."
                    },
                    "command": {
                        "type": "string",
                        "description": "Shell command to execute on the remote host."
                    },
                    "timeout_secs": {
                        "type": "integer",
                        "description": "Override the default command timeout (seconds)."
                    }
                },
                "required": ["host", "command"]
            }
        }),
        json!({
            "name": "ssh_script",
            "label": "SSH Script",
            "description": "Upload and execute a multi-line script on a remote host. The script is piped via stdin to the interpreter — no temporary files are created on the remote filesystem.",
            "parameters": {
                "type": "object",
                "properties": {
                    "host": {
                        "type": "string",
                        "description": "Host name as defined in hosts.toml."
                    },
                    "auth": {
                        "type": "string",
                        "description": "Optional exact authentication profile name."
                    },
                    "script": {
                        "type": "string",
                        "description": "Script content (bash by default). Include a shebang for other interpreters."
                    },
                    "interpreter": {
                        "type": "string",
                        "description": "Interpreter to use (default: /bin/bash)."
                    },
                    "timeout_secs": {
                        "type": "integer",
                        "description": "Override the default command timeout (seconds)."
                    }
                },
                "required": ["host", "script"]
            }
        }),
        json!({
            "name": "scp_push",
            "label": "SCP Push",
            "description": "Copy a local file to a remote host via SFTP.",
            "parameters": {
                "type": "object",
                "properties": {
                    "host": {
                        "type": "string",
                        "description": "Host name as defined in hosts.toml."
                    },
                    "auth": {
                        "type": "string",
                        "description": "Optional exact authentication profile name."
                    },
                    "local_path": {
                        "type": "string",
                        "description": "Absolute path to the local file."
                    },
                    "remote_path": {
                        "type": "string",
                        "description": "Absolute path on the remote host."
                    }
                },
                "required": ["host", "local_path", "remote_path"]
            }
        }),
        json!({
            "name": "scp_pull",
            "label": "SCP Pull",
            "description": "Copy a remote file to the local machine via SFTP.",
            "parameters": {
                "type": "object",
                "properties": {
                    "host": {
                        "type": "string",
                        "description": "Host name as defined in hosts.toml."
                    },
                    "auth": {
                        "type": "string",
                        "description": "Optional exact authentication profile name."
                    },
                    "remote_path": {
                        "type": "string",
                        "description": "Absolute path on the remote host."
                    },
                    "local_path": {
                        "type": "string",
                        "description": "Absolute path to write locally."
                    }
                },
                "required": ["host", "remote_path", "local_path"]
            }
        }),
        json!({
            "name": "sftp_ls",
            "label": "SFTP List",
            "description": "List files at a path on a remote host.",
            "parameters": {
                "type": "object",
                "properties": {
                    "host": {
                        "type": "string",
                        "description": "Host name as defined in hosts.toml."
                    },
                    "auth": {
                        "type": "string",
                        "description": "Optional exact authentication profile name."
                    },
                    "path": {
                        "type": "string",
                        "description": "Absolute directory path on the remote host."
                    }
                },
                "required": ["host", "path"]
            }
        }),
        json!({
            "name": "sftp_read",
            "label": "SFTP Read",
            "description": "Read a remote file's contents without copying it locally. Returns the content as text.",
            "parameters": {
                "type": "object",
                "properties": {
                    "host": {
                        "type": "string",
                        "description": "Host name as defined in hosts.toml."
                    },
                    "auth": {
                        "type": "string",
                        "description": "Optional exact authentication profile name."
                    },
                    "path": {
                        "type": "string",
                        "description": "Absolute file path on the remote host."
                    },
                    "max_bytes": {
                        "type": "integer",
                        "description": "Maximum bytes to read (default: max_output_bytes from config)."
                    }
                },
                "required": ["host", "path"]
            }
        }),
        json!({
            "name": "ssh_tunnel_open",
            "label": "SSH Tunnel Open",
            "description": "Open a port-forward tunnel through an SSH host. Supports local-to-remote forwarding.",
            "parameters": {
                "type": "object",
                "properties": {
                    "host": {
                        "type": "string",
                        "description": "SSH host to tunnel through (from hosts.toml)."
                    },
                    "local_port": {
                        "type": "integer",
                        "description": "Local port to listen on."
                    },
                    "remote_host": {
                        "type": "string",
                        "description": "Remote destination host (as seen from the SSH host). Default: 127.0.0.1."
                    },
                    "remote_port": {
                        "type": "integer",
                        "description": "Remote destination port."
                    }
                },
                "required": ["host", "local_port", "remote_port"]
            }
        }),
        json!({
            "name": "ssh_tunnel_close",
            "label": "SSH Tunnel Close",
            "description": "Close an open tunnel by its ID.",
            "parameters": {
                "type": "object",
                "properties": {
                    "tunnel_id": {
                        "type": "string",
                        "description": "Tunnel ID returned by ssh_tunnel_open."
                    }
                },
                "required": ["tunnel_id"]
            }
        }),
        json!({
            "name": "ssh_tunnel_list",
            "label": "SSH Tunnel List",
            "description": "List all active tunnels with their endpoints and status.",
            "parameters": {
                "type": "object",
                "properties": {}
            }
        }),
        json!({
            "name": "ssh_hosts",
            "label": "SSH Hosts",
            "description": "List all configured hosts with their address, user, port, and identity label.",
            "parameters": {
                "type": "object",
                "properties": {}
            }
        }),
        json!({
            "name": "ssh_ping",
            "label": "SSH Ping",
            "description": "Test connectivity and authentication to a host. Returns success/failure and latency.",
            "parameters": {
                "type": "object",
                "properties": {
                    "host": {
                        "type": "string",
                        "description": "Host name as defined in hosts.toml."
                    },
                    "auth": {
                        "type": "string",
                        "description": "Optional exact authentication profile name."
                    }
                },
                "required": ["host"]
            }
        }),
        json!({
            "name": "ssh_public_key",
            "label": "SSH Public Key",
            "description": "Return the OpenSSH public key and fingerprint for a configured public-key profile.",
            "parameters": {
                "type": "object",
                "properties": {
                    "host": {
                        "type": "string",
                        "description": "Host name as defined in hosts.toml."
                    },
                    "auth": {
                        "type": "string",
                        "description": "Optional exact public-key authentication profile name."
                    }
                },
                "required": ["host"]
            }
        }),
        json!({
            "name": "ssh_migrate_analyze",
            "label": "SSH Migration Analyzer",
            "description": "Scan the local ~/.ssh/ directory and produce a migration plan for shuttle. Parses ssh config, inventories key files, suggests identity_label groupings, and generates a draft hosts.toml. Does not read private key content — only filenames and config structure.",
            "parameters": {
                "type": "object",
                "properties": {}
            }
        }),
    ]
}
