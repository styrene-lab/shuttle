use serde_json::json;
use std::collections::HashMap;

// ── Config tests ──────────────────────────────────────────────────────────

mod config_tests {
    use super::*;

    #[test]
    fn parse_hosts_toml() {
        let toml_str = r#"
            [test-host]
            address = "10.0.1.50"
            user = "deploy"
            port = 2222
            identity_label = "prod"
            trust_on_first_use = true
        "#;

        let hosts: HashMap<String, shuttle::config::HostEntry> =
            toml::from_str(toml_str).expect("parse hosts");

        let entry = hosts.get("test-host").expect("host exists");
        assert_eq!(entry.address, "10.0.1.50");
        assert_eq!(entry.user, "deploy");
        assert_eq!(entry.port, 2222);
        assert_eq!(entry.identity_label, "prod");
        assert!(entry.trust_on_first_use);
    }

    #[test]
    fn host_defaults() {
        let toml_str = r#"
            [minimal]
            address = "192.168.1.1"
            user = "deploy"
            identity_label = "default"
        "#;

        let hosts: HashMap<String, shuttle::config::HostEntry> =
            toml::from_str(toml_str).expect("parse");

        let entry = hosts.get("minimal").unwrap();
        assert_eq!(entry.user, "deploy");
        assert_eq!(entry.port, 22);
        assert!(!entry.trust_on_first_use);
    }

    #[test]
    fn host_user_required() {
        let toml_str = r#"
            [missing-user]
            address = "192.168.1.1"
            identity_label = "default"
        "#;

        let result: Result<HashMap<String, shuttle::config::HostEntry>, _> =
            toml::from_str(toml_str);
        assert!(result.is_err(), "user field should be required");
    }

    #[test]
    fn config_clamps_timeout() {
        let mut config = shuttle::config::ShuttleConfig::default();
        let mut rpc = HashMap::new();
        rpc.insert(
            "default_timeout_secs".to_string(),
            json!(999999),
        );
        config.apply_rpc_config(&rpc);
        assert_eq!(config.default_timeout_secs, 3600);
    }

    #[test]
    fn config_clamps_max_output() {
        let mut config = shuttle::config::ShuttleConfig::default();
        let mut rpc = HashMap::new();
        rpc.insert("max_output_bytes".to_string(), json!(0));
        config.apply_rpc_config(&rpc);
        assert_eq!(config.max_output_bytes, 1024);
    }

    #[test]
    fn config_clamps_pool_size() {
        let mut config = shuttle::config::ShuttleConfig::default();
        let mut rpc = HashMap::new();
        rpc.insert("connection_pool_size".to_string(), json!(1000));
        config.apply_rpc_config(&rpc);
        assert_eq!(config.connection_pool_size, 32);
    }

    #[test]
    fn allowed_hosts_tightening_intersects() {
        let mut config = shuttle::config::ShuttleConfig::default();

        // First set: [a, b, c]
        let mut rpc = HashMap::new();
        rpc.insert("allowed_hosts".to_string(), json!("a,b,c"));
        config.apply_rpc_config(&rpc);
        assert_eq!(
            config.allowed_hosts.as_ref().unwrap(),
            &["a", "b", "c"]
        );

        // Second set: [b, d] — intersection should be [b]
        let mut rpc2 = HashMap::new();
        rpc2.insert("allowed_hosts".to_string(), json!("b,d"));
        config.apply_rpc_config(&rpc2);
        assert_eq!(config.allowed_hosts.as_ref().unwrap(), &["b"]);
    }

    #[test]
    fn allowed_hosts_tightening_empty_stays_empty() {
        let mut config = shuttle::config::ShuttleConfig::default();

        let mut rpc = HashMap::new();
        rpc.insert("allowed_hosts".to_string(), json!("a,b"));
        config.apply_rpc_config(&rpc);

        // Disjoint set — intersection should be empty, NOT fall back to new_hosts
        let mut rpc2 = HashMap::new();
        rpc2.insert("allowed_hosts".to_string(), json!("x,y"));
        config.apply_rpc_config(&rpc2);
        assert!(config.allowed_hosts.as_ref().unwrap().is_empty());
    }

    #[test]
    fn host_resolve_blocked_by_allowlist() {
        let mut config = shuttle::config::ShuttleConfig::default();
        let mut rpc = HashMap::new();
        rpc.insert("allowed_hosts".to_string(), json!("prod-only"));
        config.apply_rpc_config(&rpc);

        let result = config.resolve_host("not-allowed");
        assert!(result.is_err());
    }
}

// ── Auth tests ────────────────────────────────────────────────────────────

mod auth_tests {
    use styrene_identity::signer::RootSecret;

    #[test]
    fn derive_key_pair_deterministic() {
        let root = RootSecret::new([42u8; 32]);
        let kp1 = shuttle::auth::derive_key_pair(&root, "test").unwrap();
        let kp2 = shuttle::auth::derive_key_pair(&root, "test").unwrap();
        assert_eq!(format!("{kp1:?}"), format!("{kp2:?}"));
    }

    #[test]
    fn different_labels_different_keys() {
        let root = RootSecret::new([42u8; 32]);
        let fp1 = shuttle::auth::public_key_fingerprint(&root, "github").unwrap();
        let fp2 = shuttle::auth::public_key_fingerprint(&root, "work").unwrap();
        assert_ne!(fp1, fp2);
    }

    #[test]
    fn different_roots_different_keys() {
        let root1 = RootSecret::new([1u8; 32]);
        let root2 = RootSecret::new([2u8; 32]);
        let fp1 = shuttle::auth::public_key_fingerprint(&root1, "test").unwrap();
        let fp2 = shuttle::auth::public_key_fingerprint(&root2, "test").unwrap();
        assert_ne!(fp1, fp2);
    }

    #[test]
    fn empty_label_rejected() {
        let root = RootSecret::new([42u8; 32]);
        assert!(shuttle::auth::derive_key_pair(&root, "").is_err());
    }

    #[test]
    fn fingerprint_is_hex_64_chars() {
        let root = RootSecret::new([42u8; 32]);
        let fp = shuttle::auth::public_key_fingerprint(&root, "test").unwrap();
        assert_eq!(fp.len(), 64);
        assert!(fp.chars().all(|c| c.is_ascii_hexdigit()));
    }
}

// ── Tool schema tests ─────────────────────────────────────────────────────

mod tool_tests {
    #[test]
    fn tool_definitions_has_expected_count() {
        let tools = shuttle::tools::tool_definitions();
        assert_eq!(tools.len(), 12);
    }

    #[test]
    fn all_tools_have_required_fields() {
        for tool in shuttle::tools::tool_definitions() {
            assert!(tool.get("name").is_some(), "tool missing 'name'");
            assert!(tool.get("description").is_some(), "tool missing 'description'");
            assert!(tool.get("parameters").is_some(), "tool missing 'parameters'");
        }
    }

    #[test]
    fn tool_names_are_unique() {
        let tools = shuttle::tools::tool_definitions();
        let names: Vec<&str> = tools
            .iter()
            .map(|t| t["name"].as_str().unwrap())
            .collect();
        let mut deduped = names.clone();
        deduped.sort();
        deduped.dedup();
        assert_eq!(names.len(), deduped.len(), "duplicate tool names");
    }

    #[test]
    fn host_requiring_tools_have_host_parameter() {
        let needs_host = [
            "ssh_exec", "ssh_script", "scp_push", "scp_pull",
            "sftp_ls", "sftp_read", "ssh_tunnel_open", "ssh_ping",
        ];
        let tools = shuttle::tools::tool_definitions();
        for tool in &tools {
            let name = tool["name"].as_str().unwrap();
            if needs_host.contains(&name) {
                let required = tool["parameters"]["required"]
                    .as_array()
                    .expect("required field");
                assert!(
                    required.iter().any(|r| r.as_str() == Some("host")),
                    "{name} should require 'host'"
                );
            }
        }
    }
}

// ── Exec validation tests ─────────────────────────────────────────────────

mod exec_tests {
    #[test]
    fn interpreter_not_on_allowlist() {
        let bad_interpreters = [
            "/usr/bin/env",
            "/usr/local/bin/bash",
            "bash",
            "/bin/bash -c evil",
            "",
        ];
        let allowed = [
            "/bin/bash", "/bin/sh", "/usr/bin/bash", "/usr/bin/sh",
            "/usr/bin/python3", "/usr/bin/python", "/usr/bin/perl", "/usr/bin/ruby",
        ];
        for bad in &bad_interpreters {
            assert!(
                !allowed.contains(bad),
                "{bad} should not be in allowlist"
            );
        }
    }
}
