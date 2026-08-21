use serde_json::{json, Value};

use crate::client::WizClient;
use crate::format::{print_dry_run, print_output};
use crate::ids::read_ids;

use super::Operation;

pub const MUTATION: &str = r#"mutation UpdateIssue($issueId: ID!, $patch: UpdateIssuePatch) {
  updateIssue(input: {id: $issueId, patch: $patch}) {
    issue { id status resolutionReason dueAt rejectionExpiredAt }
  }
}"#;

pub fn build_operation(id: &str, status: &str) -> Result<Operation, String> {
    let status = status.to_ascii_uppercase();
    if !["OPEN", "IN_PROGRESS"].contains(&status.as_str()) {
        return Err(format!(
            "invalid status '{status}'; valid values: OPEN, IN_PROGRESS"
        ));
    }
    Ok(Operation {
        query: MUTATION,
        variables: json!({ "issueId": id, "patch": { "status": status } }),
    })
}

pub async fn run(
    ids_argument: &str,
    status: &str,
    dry_run: bool,
    human: bool,
) -> Result<(), String> {
    let ids = read_ids(ids_argument)?;
    let operations = ids
        .iter()
        .map(|id| build_operation(id, status))
        .collect::<Result<Vec<_>, _>>()?;
    if dry_run {
        return print_dry_run(&operations, human);
    }

    let client = WizClient::new().await?;
    let mut results = Vec::with_capacity(operations.len());
    let mut failures = 0;
    for (id, operation) in ids.iter().zip(&operations) {
        match client
            .graphql(operation.query, operation.variables.clone())
            .await
        {
            Ok(response) => results.push(json!({
                "id": id,
                "operation": "updateIssue",
                "success": true,
                "response": response
            })),
            Err(error) => {
                failures += 1;
                results.push(json!({
                    "id": id,
                    "operation": "updateIssue",
                    "success": false,
                    "error": error
                }));
            }
        }
    }
    print_output(&Value::Array(results), human)?;
    if failures > 0 {
        Err(format!("{failures} status operation(s) failed"))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_status_variables() {
        assert_eq!(
            build_operation("issue-1", "in_progress")
                .expect("valid status")
                .variables,
            json!({ "issueId": "issue-1", "patch": { "status": "IN_PROGRESS" } })
        );
    }
}
