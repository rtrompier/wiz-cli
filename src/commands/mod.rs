use serde::Serialize;
use serde_json::Value;

pub mod assign;
pub mod close;
pub mod evidence;
pub mod graphql;
pub mod history;
pub mod issue;
pub mod issue_engine;
pub mod issues;
pub mod note;
pub mod status;
pub mod threat;
pub mod threats;
pub mod whoami;

#[derive(Clone, Serialize)]
pub struct Operation {
    pub query: &'static str,
    pub variables: Value,
}
