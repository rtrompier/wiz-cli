use serde_json::{json, Map, Value};
use std::collections::HashMap;

use crate::client::WizClient;
use crate::format::{print_dry_run, print_output};
use crate::ids::read_ids;
use crate::time::{format_timestamp, unix_now};

use super::Operation;

pub const REASON_HELP: &str = "Resolution reason.\n\nGeneral issue reasons:\n  OBJECT_DELETED, ISSUE_FIXED, CONTROL_CHANGED, CONTROL_DISABLED, CONTROL_DELETED,\n  FALSE_POSITIVE, EXCEPTION, WONT_FIX, DETECTION_EXPIRED, SEVERITY_CHANGED\n\nThreat-only reasons:\n  MALICIOUS_THREAT, NOT_MALICIOUS_THREAT, SECURITY_TEST_THREAT,\n  PLANNED_ACTION_THREAT, INCONCLUSIVE_THREAT\n\nFALSE_POSITIVE, EXCEPTION and WONT_FIX map to REJECTED. Every other reason maps to\nRESOLVED, including every threat-only reason: the API refuses REJECTED for threat\nissues.";

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
const REJECTED_REASONS: &[&str] = &["FALSE_POSITIVE", "EXCEPTION", "WONT_FIX"];
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
    note: Option<&str>,
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
    if let Some(text) = note {
        patch.insert("note".to_string(), json!(text));
    }
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
    let operations = ids
        .iter()
        .map(|id| build_operation(id, &normalized_reason, note, rejection_expires_days, now))
        .collect::<Result<Vec<_>, _>>()?;
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

    for (id, operation) in ids.iter().zip(operations) {
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

        match client.graphql(operation.query, operation.variables).await {
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
    fn builds_patch_variables() {
        // (reason, note, rejection_expires_days, expected patch)
        let cases = [
            (
                "wont_fix",
                None,
                None,
                json!({ "status": "REJECTED", "resolutionReason": "WONT_FIX" }),
            ),
            (
                "issue_fixed",
                None,
                None,
                json!({ "status": "RESOLVED", "resolutionReason": "ISSUE_FIXED" }),
            ),
            (
                "false_positive",
                Some("known scanner"),
                None,
                json!({
                    "status": "REJECTED",
                    "resolutionReason": "FALSE_POSITIVE",
                    "note": "known scanner"
                }),
            ),
            (
                "exception",
                None,
                Some(90),
                json!({
                    "status": "REJECTED",
                    "resolutionReason": "EXCEPTION",
                    "rejectionExpiredAt": "2024-02-12T22:13:20Z"
                }),
            ),
        ];

        for (reason, note, expiry, expected_patch) in cases {
            assert_eq!(
                build_operation("issue-1", reason, note, expiry, 1_700_000_000)
                    .expect("valid close")
                    .variables,
                json!({ "issueId": "issue-1", "patch": expected_patch }),
                "reason {reason}"
            );
        }
    }

    #[test]
    fn builds_threat_reason_variables_as_resolved() {
        for reason in THREAT_REASONS {
            assert_eq!(
                build_operation("issue-1", reason, None, None, 1_700_000_000)
                    .expect("valid close")
                    .variables,
                json!({
                    "issueId": "issue-1",
                    "patch": { "status": "RESOLVED", "resolutionReason": reason }
                })
            );
        }
    }

    #[test]
    fn rejects_rejection_expiry_for_a_resolved_reason() {
        assert!(build_operation(
            "issue-1",
            "not_malicious_threat",
            None,
            Some(90),
            1_700_000_000
        )
        .is_err());
    }
}
