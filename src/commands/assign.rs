use serde_json::json;

use crate::client::WizClient;
use crate::format::{print_dry_run, print_output};
use crate::ids::read_ids;

use super::Operation;

const MUTATION: &str = r#"mutation UpdateIssuesAssignee($input: UpdateIssuesAssigneeInput!) {
  updateIssuesAssignee(input: $input) { issues { id } }
}"#;

pub fn build_operation(ids: &[String], assignee: &str) -> Operation {
    Operation {
        query: MUTATION,
        variables: json!({ "input": { "issueIds": ids, "assignee": assignee } }),
    }
}

pub async fn run(
    ids_argument: &str,
    assignee: &str,
    dry_run: bool,
    human: bool,
) -> Result<(), String> {
    let ids = read_ids(ids_argument)?;
    let operation = build_operation(&ids, assignee);
    if dry_run {
        return print_dry_run(&[operation], human);
    }

    let client = WizClient::new().await?;
    let response = client.graphql(operation.query, operation.variables).await?;
    print_output(&response, human)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_one_assignment_for_every_id() {
        let ids = vec!["a".to_string(), "b".to_string(), "c".to_string()];
        assert_eq!(
            build_operation(&ids, "owner@example.com").variables,
            json!({
                "input": {
                    "issueIds": ["a", "b", "c"],
                    "assignee": "owner@example.com"
                }
            })
        );
    }
}
