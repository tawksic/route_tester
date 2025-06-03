use std::fs;
use std::io::ErrorKind;
use std::net::Ipv4Addr;
use std::time::{SystemTime, UNIX_EPOCH};

pub enum SecretValue {
    Str(String),
    Int(i32),
    Ip(Ipv4Addr),
}

fn read_secrets_file() -> Result<String, Box<dyn std::error::Error>> {
    fs::read_to_string(".secrets.yaml").map_err(|e| match e.kind() {
        ErrorKind::NotFound => {
            Box::<dyn std::error::Error>::from("Configuration file '.secrets.yaml' not found")
        }
        ErrorKind::PermissionDenied => {
            Box::<dyn std::error::Error>::from("Permission denied reading '.secrets.yaml'")
        }
        _ => Box::<dyn std::error::Error>::from(format!("Failed to read '.secrets.yaml': {}", e)),
    })
}

fn find_key_value(content: &str, key: &str) -> Result<String, Box<dyn std::error::Error>> {
    for line in content.lines() {
        let line = line.trim();
        if line.starts_with('#') || line.is_empty() {
            continue;
        }

        if let Some((k, v)) = line.split_once(':') {
            if k.trim() == key {
                return Ok(v.trim().to_string());
            }
        }
    }

    Err(Box::<dyn std::error::Error>::from(format!(
        "Key '{}' not found in .secrets.yaml",
        key
    )))
}

pub fn get_secret_string(key: &str) -> Result<String, Box<dyn std::error::Error>> {
    let content = read_secrets_file()?;
    find_key_value(&content, key)
}

pub fn get_secret_ip(key: &str) -> Result<Ipv4Addr, Box<dyn std::error::Error>> {
    let content = read_secrets_file()?;
    let value = find_key_value(&content, key)?;

    value.parse::<Ipv4Addr>().map_err(|_| {
        Box::<dyn std::error::Error>::from(format!(
            "Key '{}' value '{}' is not a valid IP address",
            key, value
        ))
    })
}

pub fn get_secret_int(key: &str) -> Result<i32, Box<dyn std::error::Error>> {
    let content = read_secrets_file()?;
    let value = find_key_value(&content, key)?;

    value.parse::<i32>().map_err(|_| {
        Box::<dyn std::error::Error>::from(format!(
            "Key '{}' value '{}' is not a valid integer",
            key, value
        ))
    })
}

pub fn rand() -> u16 {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .subsec_nanos();

    return nanos as u16;
}

// Todo - add these to make it pretty
pub fn print_green(input_text: Vec<String>) {
    println!("\x1b[92m{:?}\x1b[0m", input_text);
}

pub fn print_yellow(input_text: String) {
    println!("\x1b[93m{}\x1b[0m", input_text);
}

pub fn print_red(input_text: String) {
    println!("\x1b[91m{}\x1b[0m", input_text);
}
