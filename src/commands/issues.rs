use crate::client::WizClient;
use crate::format::print_output;
use crate::time::unix_now;

use super::issue_engine::{self, IssueFilterArgs};

pub async fn run(
    filters: &IssueFilterArgs,
    number: usize,
    all: bool,
    threat_mode: bool,
    human: bool,
) -> Result<(), String> {
    let now = unix_now()?;
    let filters = if threat_mode {
        issue_engine::pin_threat_filter(filters, now)?
    } else {
        issue_engine::build_filters(filters, now)?
    };
    let client = WizClient::new().await?;
    let output = issue_engine::fetch_connection(&client, filters, number, all, threat_mode).await?;
    print_output(&output, human)
}
