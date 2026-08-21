use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::env;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use crate::time::unix_now;

const DEFAULT_AUTH_URL: &str = "https://auth.app.wiz.io/oauth/token";

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    expires_in: i64,
}

#[derive(Deserialize, Serialize)]
struct CachedToken {
    access_token: String,
    expires_at: i64,
}

pub struct WizClient {
    client: Client,
    api_url: String,
    token: String,
}

impl WizClient {
    pub async fn new() -> Result<Self, String> {
        let client_id = env::var("WIZ_CLIENT_ID").map_err(|_| "WIZ_CLIENT_ID not set")?;
        let client_secret =
            env::var("WIZ_CLIENT_SECRET").map_err(|_| "WIZ_CLIENT_SECRET not set")?;
        let api_url = env::var("WIZ_API_URL").map_err(|_| {
            "WIZ_API_URL not set (your tenant's GraphQL endpoint, e.g. https://api.<region>.app.wiz.io/graphql)"
        })?;
        let auth_url = env::var("WIZ_AUTH_URL").unwrap_or_else(|_| DEFAULT_AUTH_URL.to_string());
        let client = Client::new();
        let now = unix_now()?;
        let cache_path = token_cache_path()?;

        let token = if let Some(token) = read_cached_token(&cache_path, now) {
            token
        } else {
            let token = fetch_token(&client, &auth_url, &client_id, &client_secret).await?;
            let expires_at = now
                .checked_add(token.expires_in)
                .ok_or_else(|| "token expiry is too large".to_string())?;
            if let Err(error) = write_cached_token(
                &cache_path,
                &CachedToken {
                    access_token: token.access_token.clone(),
                    expires_at,
                },
            ) {
                eprintln!("Warning: {error}");
            }
            token.access_token
        };

        Ok(Self {
            client,
            api_url,
            token,
        })
    }

    pub fn access_token(&self) -> &str {
        &self.token
    }

    pub async fn graphql(&self, query: &str, variables: Value) -> Result<Value, String> {
        let response = self
            .client
            .post(&self.api_url)
            .bearer_auth(&self.token)
            .json(&json!({ "query": query, "variables": variables }))
            .send()
            .await
            .map_err(|e| e.to_string())?;
        let status = response.status();
        let body = response.text().await.map_err(|e| e.to_string())?;

        if !status.is_success() {
            return Err(format!("HTTP {status}: {body}"));
        }

        let value: Value = serde_json::from_str(&body)
            .map_err(|e| format!("invalid JSON response from Wiz: {e}"))?;
        if let Some(errors) = value.get("errors").and_then(Value::as_array) {
            if !errors.is_empty() {
                let messages = errors
                    .iter()
                    .map(|error| {
                        error
                            .get("message")
                            .and_then(Value::as_str)
                            .map(str::to_string)
                            .unwrap_or_else(|| error.to_string())
                    })
                    .collect::<Vec<_>>()
                    .join("; ");
                return Err(format!("GraphQL errors: {messages}"));
            }
        }
        Ok(value)
    }
}

async fn fetch_token(
    client: &Client,
    auth_url: &str,
    client_id: &str,
    client_secret: &str,
) -> Result<TokenResponse, String> {
    let body = format!(
        "grant_type=client_credentials&client_id={}&client_secret={}&audience=wiz-api",
        form_encode(client_id),
        form_encode(client_secret)
    );
    let response = client
        .post(auth_url)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(body)
        .send()
        .await
        .map_err(|e| e.to_string())?;
    let status = response.status();
    let body = response.text().await.map_err(|e| e.to_string())?;
    if !status.is_success() {
        return Err(format!("HTTP {status}: {body}"));
    }
    serde_json::from_str(&body).map_err(|e| format!("invalid OAuth token response: {e}"))
}

fn form_encode(input: &str) -> String {
    let mut output = String::with_capacity(input.len());
    for byte in input.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                output.push(char::from(byte));
            }
            b' ' => output.push('+'),
            _ => output.push_str(&format!("%{byte:02X}")),
        }
    }
    output
}

fn token_cache_path() -> Result<PathBuf, String> {
    if let Some(path) = env::var_os("XDG_CACHE_HOME").filter(|value| !value.is_empty()) {
        return Ok(PathBuf::from(path).join("wiz-cli/token.json"));
    }
    let home = env::var_os("HOME").ok_or("HOME not set and XDG_CACHE_HOME not set")?;
    Ok(PathBuf::from(home).join(".cache/wiz-cli/token.json"))
}

fn read_cached_token(path: &Path, now: i64) -> Option<String> {
    if let Some(directory) = path.parent() {
        if directory.exists()
            && fs::set_permissions(directory, fs::Permissions::from_mode(0o700)).is_err()
        {
            return None;
        }
    }
    if path.exists() && fs::set_permissions(path, fs::Permissions::from_mode(0o600)).is_err() {
        return None;
    }
    let content = fs::read_to_string(path).ok()?;
    let cached: CachedToken = serde_json::from_str(&content).ok()?;
    (now.checked_add(60)? < cached.expires_at).then_some(cached.access_token)
}

fn write_cached_token(path: &Path, token: &CachedToken) -> Result<(), String> {
    let directory = path
        .parent()
        .ok_or_else(|| "token cache path has no parent directory".to_string())?;
    fs::create_dir_all(directory)
        .map_err(|e| format!("failed to create token cache directory: {e}"))?;
    fs::set_permissions(directory, fs::Permissions::from_mode(0o700))
        .map_err(|e| format!("failed to secure token cache directory: {e}"))?;
    let content =
        serde_json::to_vec(token).map_err(|e| format!("failed to serialize token cache: {e}"))?;
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| format!("failed to open token cache: {e}"))?;
    file.set_permissions(fs::Permissions::from_mode(0o600))
        .map_err(|e| format!("failed to secure token cache: {e}"))?;
    file.write_all(&content)
        .map_err(|e| format!("failed to write token cache: {e}"))
}
