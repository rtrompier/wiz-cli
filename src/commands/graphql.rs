use serde_json::{Map, Value};

use crate::client::WizClient;
use crate::format::print_output;

pub async fn run(query: &str, variables: Option<&str>, human: bool) -> Result<(), String> {
    let variables = match variables {
        Some(value) => serde_json::from_str(value)
            .map_err(|e| format!("invalid JSON passed to --vars: {e}"))?,
        None => Value::Object(Map::new()),
    };
    let client = WizClient::new().await?;
    let response = client.graphql(query, variables).await?;
    print_output(&response, human)
}
