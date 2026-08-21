use super::issue_engine::IssueFilterArgs;

pub async fn run(
    filters: &IssueFilterArgs,
    number: usize,
    all: bool,
    human: bool,
) -> Result<(), String> {
    super::issues::run(filters, number, all, true, human).await
}
