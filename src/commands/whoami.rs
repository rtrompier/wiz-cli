use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde_json::{json, Value};

use crate::client::WizClient;
use crate::format::print_output;
use crate::time::{format_timestamp, unix_now};

pub async fn run(human: bool) -> Result<(), String> {
    let client = WizClient::new().await?;
    let claims = decode_claims(client.access_token())?;
    let now = unix_now()?;
    let expiry = claims.get("exp").and_then(Value::as_i64);
    let expires_at = expiry.map(format_timestamp);
    let remaining = expiry.map(|value| value.saturating_sub(now));
    let scopes = extract_scopes(&claims);
    let identity = json!({
        "subject": claims.get("sub").cloned().unwrap_or(Value::Null),
        "email": claims.get("email").cloned().unwrap_or(Value::Null),
        "isServiceAccount": claims.get("isServiceAccount").cloned().unwrap_or(Value::Null),
        "tenant": claims.get("tsn").cloned().unwrap_or(Value::Null),
        "tenantId": claims.get("tid").cloned().unwrap_or(Value::Null),
        "dataCenter": claims.get("dc").cloned().unwrap_or(Value::Null),
        "scopes": scopes,
        // Wiz packs granted permissions into `encodedScopes`, an opaque base64 bitmask
        // with no public decoding table, so a readable scope list is not available here.
        "encodedScopes": claims.get("encodedScopes").cloned().unwrap_or(Value::Null),
        "audience": claims.get("aud").cloned().unwrap_or(Value::Null),
        "issuer": claims.get("iss").cloned().unwrap_or(Value::Null),
        "expiresAt": expires_at,
        "timeRemainingSeconds": remaining
    });

    if human {
        print_identity(&identity);
        Ok(())
    } else {
        print_output(&identity, false)
    }
}

fn decode_claims(token: &str) -> Result<Value, String> {
    let payload = token
        .split('.')
        .nth(1)
        .ok_or("OAuth access token is not a JWT")?;
    let decoded = URL_SAFE_NO_PAD
        .decode(payload)
        .map_err(|e| format!("failed to decode JWT payload: {e}"))?;
    serde_json::from_slice(&decoded).map_err(|e| format!("invalid JWT payload: {e}"))
}

fn extract_scopes(claims: &Value) -> Vec<String> {
    claims
        .get("scope")
        .or_else(|| claims.get("scopes"))
        .map(|value| match value {
            Value::String(scopes) => scopes.split_whitespace().map(str::to_string).collect(),
            Value::Array(scopes) => scopes
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect(),
            _ => Vec::new(),
        })
        .unwrap_or_default()
}

fn print_identity(identity: &Value) {
    println!("Subject: {}", display_claim(&identity["subject"]));
    println!("Email: {}", display_claim(&identity["email"]));
    println!(
        "Service account: {}",
        display_claim(&identity["isServiceAccount"])
    );
    println!("Tenant: {}", display_claim(&identity["tenant"]));
    println!("Data center: {}", display_claim(&identity["dataCenter"]));
    println!("Audience: {}", display_claim(&identity["audience"]));
    println!("Issuer: {}", display_claim(&identity["issuer"]));
    println!("Expires: {}", display_claim(&identity["expiresAt"]));
    println!(
        "Time remaining: {}",
        identity["timeRemainingSeconds"]
            .as_i64()
            .map(|seconds| format!("{seconds} seconds"))
            .unwrap_or_else(|| "-".to_string())
    );
    println!("Scopes:");
    match identity["scopes"].as_array() {
        Some(scopes) if !scopes.is_empty() => {
            for scope in scopes {
                println!("  {}", display_claim(scope));
            }
        }
        _ => {
            println!("  (not listed in the token)");
            println!(
                "  Wiz packs permissions into an opaque `encodedScopes` bitmask, so the granted"
            );
            println!(
                "  scopes cannot be decoded locally. Check them in the Wiz UI under the service"
            );
            println!("  account, or probe a command and read the error.");
        }
    }
}

fn display_claim(value: &Value) -> String {
    match value {
        Value::Null => "-".to_string(),
        Value::String(value) => value.clone(),
        _ => value.to_string(),
    }
}
