use crate::client::WizClient;
use crate::format::print_output;

pub async fn run(id: &str, threat_mode: bool, human: bool) -> Result<(), String> {
    let client = WizClient::new().await?;
    let issue = super::issue_engine::fetch_one(&client, id, threat_mode).await?;
    print_output(&issue, human)
}
