use mediaflow_proxy_light::config::Config;
use std::sync::{Mutex, MutexGuard};
use std::{env, fs};

static ENV_LOCK: Mutex<()> = Mutex::new(());

fn setup() -> MutexGuard<'static, ()> {
    let guard = ENV_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    env::remove_var("APP__SERVER__HOST");
    env::remove_var("APP__SERVER__PORT");
    env::remove_var("APP__AUTH__API_PASSWORD");
    env::remove_var("APP__AUTH__TOKEN_TTL");
    env::remove_var("APP__PROXY__CONNECT_TIMEOUT");
    env::remove_var("API_PASSWORD");
    env::remove_var("APP__FORWARD__PUBLIC_IP");
    env::remove_var("CONFIG_PATH");
    guard
}

#[test]
fn test_config_from_env() {
    let _guard = setup();

    // Set environment variables
    env::set_var("APP__SERVER__HOST", "127.0.0.1");
    env::set_var("APP__SERVER__PORT", "8888"); // Match the default port in Config
    env::set_var("APP__AUTH__API_PASSWORD", "test_password");
    env::set_var("APP__PROXY__CONNECT_TIMEOUT", "7");

    let config = Config::from_env().unwrap();

    // Assert configuration values
    assert_eq!(config.server.host, "127.0.0.1");
    assert_eq!(config.server.port, 8888); // Updated to match default port
    assert_eq!(config.auth.api_password, "test_password");
    assert_eq!(config.proxy.connect_timeout, 7);
}

#[test]
fn token_ttl_defaults_to_48_hours_and_reads_env() {
    let _guard = setup();
    assert_eq!(Config::from_env().unwrap().auth.token_ttl, 172_800);

    env::set_var("APP__AUTH__TOKEN_TTL", "3600");
    assert_eq!(Config::from_env().unwrap().auth.token_ttl, 3600);
    env::remove_var("APP__AUTH__TOKEN_TTL");
}

#[test]
fn api_password_has_no_default() {
    let _guard = setup();
    // `main` refuses to start with an empty password.
    assert_eq!(Config::from_env().unwrap().auth.api_password, "");
}

/// The Python proxy's flat variables are no longer read: only `APP__*`.
#[test]
fn flat_python_variables_are_ignored() {
    let _guard = setup();
    env::set_var("API_PASSWORD", "flat");
    assert_eq!(Config::from_env().unwrap().auth.api_password, "");
    env::remove_var("API_PASSWORD");
}

#[test]
fn reads_a_toml_file() {
    let _guard = setup();

    let config_content = r#"
[server]
host = "127.0.0.1"
port = 8888

[auth]
api_password = "test_password"
token_ttl = 600

[proxy]
connect_timeout = 12
"#;

    let temp_dir = tempfile::tempdir().expect("Failed to create temp directory");
    let config_path = temp_dir.path().join("config.toml");
    fs::write(&config_path, config_content).expect("Failed to write config");
    env::set_var("CONFIG_PATH", config_path.to_str().unwrap());

    let config = Config::from_env().unwrap();
    env::remove_var("CONFIG_PATH");

    assert_eq!(config.auth.api_password, "test_password");
    assert_eq!(config.auth.token_ttl, 600);
    assert_eq!(config.proxy.connect_timeout, 12);
    assert!(
        config.proxy.follow_redirects,
        "redirects followed by default"
    );
}

/// The password is the exact string AIO Reborn derives its token key from:
/// no numeric conversion.
#[test]
fn numeric_looking_password_is_read_verbatim() {
    let _guard = setup();
    for raw in ["00123456", "1e5", "0.50", "true"] {
        env::set_var("APP__AUTH__API_PASSWORD", raw);
        assert_eq!(Config::from_env().unwrap().auth.api_password, raw);
    }
    env::remove_var("APP__AUTH__API_PASSWORD");
}

/// The Docker images ship config-example.toml as /app/config.toml: it must
/// not set a password, or containers would start with a public one.
#[test]
fn example_config_sets_no_password() {
    let _guard = setup();
    env::set_var(
        "CONFIG_PATH",
        concat!(env!("CARGO_MANIFEST_DIR"), "/config-example.toml"),
    );
    let mut config = Config::from_env().unwrap();
    env::remove_var("CONFIG_PATH");
    assert_eq!(config.auth.api_password, "");
    assert!(config.validate().is_err(), "must refuse to start");
}

#[test]
fn validate_refuses_example_passwords_and_bad_public_ips() {
    let _guard = setup();
    let config = |password: &str, public_ip: Option<&str>| {
        let mut config = Config::from_env().unwrap();
        config.auth.api_password = password.to_string();
        config.forward.public_ip = public_ip.map(str::to_string);
        config
    };
    for password in ["", "your-password", "changeme"] {
        assert!(config(password, None).validate().is_err(), "{password:?}");
    }
    let strong = "0123456789abcdef0123";
    assert!(config(strong, Some("2a01:e0a::1")).validate().is_err());
    assert!(config(strong, Some("not an ip")).validate().is_err());

    let mut ok = config(strong, Some(" 82.66.1.2 "));
    assert_eq!(ok.validate().unwrap(), Vec::<String>::new());
    assert_eq!(ok.forward.public_ip.as_deref(), Some("82.66.1.2"));
    let mut empty = config(strong, Some(""));
    empty.validate().unwrap();
    assert_eq!(empty.forward.public_ip, None, "empty means: look it up");

    let warnings = config("short", None).validate().unwrap();
    assert_eq!(warnings.len(), 1, "{warnings:?}");
}
