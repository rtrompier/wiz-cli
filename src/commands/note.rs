use serde_json::{json, Value};

use crate::client::WizClient;
use crate::format::{print_dry_run, print_output};
use crate::ids::read_ids;

use super::Operation;

pub const MUTATION: &str = r#"mutation CreateIssueNote($input: CreateIssueNoteInput!) {
  createIssueNote(input: $input) {
    issueNote { id text createdAt user { id email } }
  }
}"#;

pub fn build_operation(id: &str, text: &str) -> Operation {
    Operation {
        query: MUTATION,
        variables: json!({ "input": { "issueId": id, "text": text } }),
    }
}

pub async fn run(ids_argument: &str, text: &str, dry_run: bool, human: bool) -> Result<(), String> {
    let ids = read_ids(ids_argument)?;
    let operations: Vec<Operation> = ids.iter().map(|id| build_operation(id, text)).collect();
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
                "operation": "createIssueNote",
                "success": true,
                "response": response
            })),
            Err(error) => {
                failures += 1;
                results.push(json!({
                    "id": id,
                    "operation": "createIssueNote",
                    "success": false,
                    "error": error
                }));
            }
        }
    }
    print_output(&Value::Array(results), human)?;
    if failures > 0 {
        Err(format!("{failures} note operation(s) failed"))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_note_variables() {
        assert_eq!(
            build_operation("issue-1", "needs review").variables,
            json!({ "input": { "issueId": "issue-1", "text": "needs review" } })
        );
    }
}
