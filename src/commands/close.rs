use serde_json::{json, Map, Value};
use std::collections::HashMap;

use crate::client::WizClient;
use crate::format::{print_dry_run, print_output};
use crate::ids::read_ids;
use crate::time::{format_timestamp, unix_now};

use super::Operation;

pub const REASON_HELP: &str = "Resolution reason.\n\nGeneral issue reasons:\n  OBJECT_DELETED, ISSUE_FIXED, CONTROL_CHANGED, CONTROL_DISABLED, CONTROL_DELETED,\n  FALSE_POSITIVE, EXCEPTION, WONT_FIX, DETECTION_EXPIRED, SEVERITY_CHANGED\n\nThreat-only reasons:\n  MALICIOUS_THREAT, NOT_MALICIOUS_THREAT, SECURITY_TEST_THREAT,\n  PLANNED_ACTION_THREAT, INCONCLUSIVE_THREAT\n\nFALSE_POSITIVE, EXCEPTION, WONT_FIX, NOT_MALICIOUS_THREAT, SECURITY_TEST_THREAT,\nPLANNED_ACTION_THREAT, and INCONCLUSIVE_THREAT map to REJECTED. Every other reason\nmaps to RESOLVED.";

const REASONS: &[&str] = &[
    "OBJECT_DELETED",
    "ISSUE_FIXED",
    "CONTROL_CHANGED",
    "CONTROL_DISABLED",
    "CONTROL_DELETED",
    "FALSE_POSITIVE",
    "EXCEPTION",
    "WONT_FIX",
    "DETECTION_EXPIRED",
    "MALICIOUS_THREAT",
    "NOT_MALICIOUS_THREAT",
    "SECURITY_TEST_THREAT",
    "PLANNED_ACTION_THREAT",
    "INCONCLUSIVE_THREAT",
    "SEVERITY_CHANGED",
];
const REJECTED_REASONS: &[&str] = &[
    "FALSE_POSITIVE",
    "EXCEPTION",
    "WONT_FIX",
    "NOT_MALICIOUS_THREAT",
    "SECURITY_TEST_THREAT",
    "PLANNED_ACTION_THREAT",
    "INCONCLUSIVE_THREAT",
];
const THREAT_REASONS: &[&str] = &[
    "MALICIOUS_THREAT",
    "NOT_MALICIOUS_THREAT",
    "SECURITY_TEST_THREAT",
    "PLANNED_ACTION_THREAT",
    "INCONCLUSIVE_THREAT",
];

pub fn build_operation(
    id: &str,
    reason: &str,
    rejection_expires_days: Option<u64>,
    now: i64,
) -> Result<Operation, String> {
    let reason = normalize_reason(reason)?;
    let status = if REJECTED_REASONS.contains(&reason.as_str()) {
        "REJECTED"
    } else {
        "RESOLVED"
    };
    if rejection_expires_days.is_some() && status != "REJECTED" {
        return Err(
            "--rejection-expires-days can only be used with a reason that maps to REJECTED"
                .to_string(),
        );
    }
    let mut patch = Map::from_iter([
        ("status".to_string(), json!(status)),
        ("resolutionReason".to_string(), json!(reason)),
    ]);
    if let Some(days) = rejection_expires_days {
        let seconds = days
            .checked_mul(86_400)
            .and_then(|value| i64::try_from(value).ok())
            .ok_or_else(|| "rejection expiry is too large".to_string())?;
        let expiry = now
            .checked_add(seconds)
            .ok_or_else(|| "rejection expiry is too large".to_string())?;
        patch.insert(
            "rejectionExpiredAt".to_string(),
            Value::String(format_timestamp(expiry)),
        );
    }
    Ok(Operation {
        query: super::status::MUTATION,
        variables: json!({ "issueId": id, "patch": patch }),
    })
}

pub async fn run(
    ids_argument: &str,
    reason: &str,
    note: Option<&str>,
    rejection_expires_days: Option<u64>,
    dry_run: bool,
    human: bool,
) -> Result<(), String> {
    let ids = read_ids(ids_argument)?;
    let normalized_reason = normalize_reason(reason)?;
    let now = unix_now()?;
    let status_operations = ids
        .iter()
        .map(|id| build_operation(id, &normalized_reason, rejection_expires_days, now))
        .collect::<Result<Vec<_>, _>>()?;
    let operations = interleave_operations(&ids, note, &status_operations);
    if dry_run {
        return print_dry_run(&operations, human);
    }

    let client = WizClient::new().await?;
    let issue_nodes = super::issue_engine::fetch_types(&client, &ids).await?;
    let issue_types: HashMap<&str, &str> = issue_nodes
        .iter()
        .filter_map(|issue| Some((issue.get("id")?.as_str()?, issue.get("type")?.as_str()?)))
        .collect();
    let threat_reason = THREAT_REASONS.contains(&normalized_reason.as_str());
    let mut results = Vec::new();
    let mut failures = 0;

    for (id, status_operation) in ids.iter().zip(&status_operations) {
        let Some(issue_type) = issue_types.get(id.as_str()) else {
            failures += 1;
            results.push(failure_result(
                id,
                "validateIssueType",
                "issue was not found",
            ));
            continue;
        };
        let is_threat = *issue_type == "THREAT_DETECTION";
        if threat_reason && !is_threat {
            failures += 1;
            results.push(failure_result(
                id,
                "validateIssueType",
                "threat-only resolution reasons require a THREAT_DETECTION issue",
            ));
            continue;
        }
        if !threat_reason && is_threat {
            failures += 1;
            results.push(failure_result(
                id,
                "validateIssueType",
                "THREAT_DETECTION issues require a threat-only resolution reason",
            ));
            continue;
        }

        if let Some(note_text) = note {
            let note_operation = super::note::build_operation(id, note_text);
            match client
                .graphql(note_operation.query, note_operation.variables)
                .await
            {
                Ok(response) => results.push(success_result(id, "createIssueNote", response)),
                Err(error) => {
                    failures += 1;
                    results.push(failure_result(id, "createIssueNote", &error));
                    continue;
                }
            }
        }

        match client
            .graphql(status_operation.query, status_operation.variables.clone())
            .await
        {
            Ok(response) => results.push(success_result(id, "updateIssue", response)),
            Err(error) => {
                failures += 1;
                results.push(failure_result(id, "updateIssue", &error));
            }
        }
    }

    print_output(&Value::Array(results), human)?;
    if failures > 0 {
        Err(format!("{failures} close operation(s) failed"))
    } else {
        Ok(())
    }
}

fn normalize_reason(reason: &str) -> Result<String, String> {
    let normalized = reason.to_ascii_uppercase();
    if REASONS.contains(&normalized.as_str()) {
        Ok(normalized)
    } else {
        Err(format!(
            "invalid resolution reason '{reason}'; valid values: {}",
            REASONS.join(", ")
        ))
    }
}

fn interleave_operations(
    ids: &[String],
    note: Option<&str>,
    status_operations: &[Operation],
) -> Vec<Operation> {
    let capacity = status_operations.len() * if note.is_some() { 2 } else { 1 };
    let mut operations = Vec::with_capacity(capacity);
    for (id, status_operation) in ids.iter().zip(status_operations) {
        if let Some(text) = note {
            operations.push(super::note::build_operation(id, text));
        }
        operations.push(status_operation.clone());
    }
    operations
}

fn success_result(id: &str, operation: &str, response: Value) -> Value {
    json!({ "id": id, "operation": operation, "success": true, "response": response })
}

fn failure_result(id: &str, operation: &str, error: &str) -> Value {
    json!({ "id": id, "operation": operation, "success": false, "error": error })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_rejected_reason_variables() {
        assert_eq!(
            build_operation("issue-1", "wont_fix", None, 1_700_000_000)
                .expect("valid close")
                .variables,
            json!({
                "issueId": "issue-1",
                "patch": { "status": "REJECTED", "resolutionReason": "WONT_FIX" }
            })
        );
    }

    #[test]
    fn builds_resolved_reason_variables() {
        assert_eq!(
            build_operation("issue-1", "issue_fixed", None, 1_700_000_000)
                .expect("valid close")
                .variables,
            json!({
                "issueId": "issue-1",
                "patch": { "status": "RESOLVED", "resolutionReason": "ISSUE_FIXED" }
            })
        );
    }

    #[test]
    fn builds_rejection_expiry_variables() {
        assert_eq!(
            build_operation("issue-1", "exception", Some(90), 1_700_000_000)
                .expect("valid close")
                .variables,
            json!({
                "issueId": "issue-1",
                "patch": {
                    "status": "REJECTED",
                    "resolutionReason": "EXCEPTION",
                    "rejectionExpiredAt": "2024-02-12T22:13:20Z"
                }
            })
        );
    }
}
