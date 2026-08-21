use clap::Args;
use serde_json::{json, Map, Value};

use crate::client::WizClient;
use crate::time::{format_timestamp, parse_duration};

pub const ISSUES_QUERY: &str = r#"query Issues(
  $first: Int
  $after: String
  $filterBy: IssueFilters
  $orderBy: IssueOrder
  $fetchThreatDetectionDetails: Boolean = false
) {
  issues: issuesV2(first: $first, after: $after, filterBy: $filterBy, orderBy: $orderBy) {
    nodes {
      id
      type
      status
      severity
      createdAt
      updatedAt
      resolvedAt
      dueAt
      rejectionExpiredAt
      resolutionReason
      resolutionNote
      resolvedBy { user { email name } }
      control { id name description severity }
      projects { id name slug businessUnit riskProfile { businessImpact } }
      entity { id name type }
      entitySnapshot {
        id type name nativeType cloudPlatform region
        subscriptionName subscriptionExternalId externalId
        kubernetesClusterName kubernetesNamespaceName tags
      }
      notes { id text }
      serviceTickets { id externalId name url }
      threatDetectionDetails @include(if: $fetchThreatDetectionDetails) {
        actorsTotalCount
        actors { id name type nativeType }
        resourcesTotalCount
        resources { id name type nativeType }
        eventOrigin
        detections(first: 0) { totalCount }
        mainDetection {
          id
          startedAt
          severity
          description(format: MARKDOWN)
          ruleMatch { rule { id name origins } }
        }
      }
    }
    pageInfo { hasNextPage endCursor }
    totalCount
  }
}"#;

const SEVERITIES: &[&str] = &["INFORMATIONAL", "LOW", "MEDIUM", "HIGH", "CRITICAL"];
const STATUSES: &[&str] = &["OPEN", "IN_PROGRESS", "RESOLVED", "REJECTED"];
const ISSUE_TYPES: &[&str] = &[
    "TOXIC_COMBINATION",
    "THREAT_DETECTION",
    "CLOUD_CONFIGURATION",
    "ATTACK_SURFACE",
    "RISK_TOXIC_COMBINATION",
];
const RESOLUTION_REASONS: &[&str] = &[
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
const BUSINESS_IMPACTS: &[&str] = &["LBI", "MBI", "HBI"];
const STACK_LAYERS: &[&str] = &[
    "APPLICATION_AND_DATA",
    "CI_CD",
    "SECURITY_AND_IDENTITY",
    "COMPUTE_PLATFORMS",
    "CODE",
    "CLOUD_ENTITLEMENTS",
    "DATA_STORES",
    "MACHINE_LEARNING_AND_AI",
    "NETWORKING",
];

#[derive(Args, Clone, Debug, Default)]
pub struct IssueFilterArgs {
    /// Issue IDs; repeat the flag or use comma-separated values
    #[arg(long, value_delimiter = ',')]
    pub id: Option<Vec<String>>,

    /// Free-text search on title or object name
    #[arg(long)]
    pub search: Option<String>,

    /// Severities; repeat the flag or use comma-separated values
    #[arg(long, value_delimiter = ',')]
    pub severity: Option<Vec<String>>,

    /// Statuses; repeat the flag or use comma-separated values
    #[arg(long, value_delimiter = ',')]
    pub status: Option<Vec<String>>,

    /// Issue types; repeat or comma-separate; invalid with threats
    #[arg(long, value_delimiter = ',')]
    pub r#type: Option<Vec<String>>,

    /// Project IDs; repeat the flag or use comma-separated values
    #[arg(long, value_delimiter = ',')]
    pub project: Option<Vec<String>>,

    /// Resolution reasons; repeat the flag or use comma-separated values
    #[arg(long, value_delimiter = ',')]
    pub resolution_reason: Option<Vec<String>>,

    /// Assignees; repeat the flag or use comma-separated values
    #[arg(long, value_delimiter = ',')]
    pub assignee: Option<Vec<String>>,

    /// Environments; repeat the flag or use comma-separated values
    #[arg(long, value_delimiter = ',')]
    pub environment: Option<Vec<String>>,

    /// Project business impacts; repeat the flag or use comma-separated values
    #[arg(long, value_delimiter = ',')]
    pub project_business_impact: Option<Vec<String>>,

    /// Stack layers; repeat the flag or use comma-separated values
    #[arg(long, value_delimiter = ',')]
    pub stack_layer: Option<Vec<String>>,

    /// Cloud account or organization IDs; repeat or use comma-separated values
    #[arg(long, value_delimiter = ',')]
    pub cloud_account: Option<Vec<String>>,

    /// Return only issues that have a note
    #[arg(long)]
    pub has_note: bool,

    /// Return only issues that have a service ticket
    #[arg(long)]
    pub has_service_ticket: bool,

    /// Return only issues whose notes contain this text
    #[arg(long)]
    pub note_contains: Option<String>,

    /// Return only issues validated as exploitable
    #[arg(long)]
    pub validated_as_exploitable: bool,

    /// Threat file hash
    #[arg(long)]
    pub threat_file_hash: Option<String>,

    /// Threat runtime program name
    #[arg(long)]
    pub threat_runtime_program_name: Option<String>,

    /// Created after this relative duration ago, such as 7d
    #[arg(long)]
    pub since: Option<String>,

    /// Created before this relative duration ago, such as 30d
    #[arg(long)]
    pub created_before: Option<String>,

    /// Resolved after this relative duration ago
    #[arg(long)]
    pub resolved_since: Option<String>,

    /// Resolved before this relative duration ago
    #[arg(long)]
    pub resolved_before: Option<String>,

    /// Status changed after this relative duration ago
    #[arg(long)]
    pub status_changed_since: Option<String>,

    /// Due before this relative duration ago
    #[arg(long)]
    pub due_before: Option<String>,

    /// Due after this relative duration ago
    #[arg(long)]
    pub due_since: Option<String>,

    /// Threat last grouped after this relative duration ago
    #[arg(long)]
    pub threat_last_grouped_since: Option<String>,
}

pub fn build_filters(args: &IssueFilterArgs, now: i64) -> Result<Map<String, Value>, String> {
    let mut filters = Map::new();
    insert_list(&mut filters, "id", args.id.as_ref());
    insert_string(&mut filters, "search", args.search.as_deref());
    insert_enum_list(&mut filters, "severity", args.severity.as_ref(), SEVERITIES)?;
    insert_enum_list(&mut filters, "status", args.status.as_ref(), STATUSES)?;
    insert_enum_list(&mut filters, "type", args.r#type.as_ref(), ISSUE_TYPES)?;
    insert_list(&mut filters, "project", args.project.as_ref());
    insert_enum_list(
        &mut filters,
        "resolutionReason",
        args.resolution_reason.as_ref(),
        RESOLUTION_REASONS,
    )?;
    insert_list(&mut filters, "assignee", args.assignee.as_ref());
    insert_list(&mut filters, "environment", args.environment.as_ref());
    insert_enum_list(
        &mut filters,
        "projectBusinessImpact",
        args.project_business_impact.as_ref(),
        BUSINESS_IMPACTS,
    )?;
    insert_enum_list(
        &mut filters,
        "stackLayer",
        args.stack_layer.as_ref(),
        STACK_LAYERS,
    )?;
    insert_list(
        &mut filters,
        "cloudAccountOrCloudOrganizationId",
        args.cloud_account.as_ref(),
    );
    if args.has_note {
        filters.insert("hasNote".to_string(), Value::Bool(true));
    }
    if args.has_service_ticket {
        filters.insert("hasServiceTicket".to_string(), Value::Bool(true));
    }
    insert_string(&mut filters, "noteContains", args.note_contains.as_deref());
    if args.validated_as_exploitable {
        filters.insert("validatedAsExploitable".to_string(), Value::Bool(true));
    }
    insert_string(
        &mut filters,
        "threatFileHash",
        args.threat_file_hash.as_deref(),
    );
    insert_string(
        &mut filters,
        "threatRuntimeProgramName",
        args.threat_runtime_program_name.as_deref(),
    );

    insert_date_range(
        &mut filters,
        "createdAt",
        args.since.as_deref(),
        args.created_before.as_deref(),
        now,
    )?;
    insert_date_range(
        &mut filters,
        "resolvedAt",
        args.resolved_since.as_deref(),
        args.resolved_before.as_deref(),
        now,
    )?;
    insert_date_range(
        &mut filters,
        "statusChangedAt",
        args.status_changed_since.as_deref(),
        None,
        now,
    )?;
    insert_date_range(
        &mut filters,
        "dueAt",
        args.due_since.as_deref(),
        args.due_before.as_deref(),
        now,
    )?;
    insert_date_range(
        &mut filters,
        "threatLastGroupedAt",
        args.threat_last_grouped_since.as_deref(),
        None,
        now,
    )?;
    Ok(filters)
}

pub fn build_variables(
    filters: Map<String, Value>,
    first: usize,
    after: Option<&str>,
    fetch_threat_detection_details: bool,
) -> Result<Value, String> {
    let first = i64::try_from(first).map_err(|_| "requested result count is too large")?;
    let mut variables = Map::new();
    variables.insert("first".to_string(), json!(first));
    variables.insert(
        "orderBy".to_string(),
        json!({ "field": "SEVERITY", "direction": "DESC" }),
    );
    variables.insert(
        "fetchThreatDetectionDetails".to_string(),
        Value::Bool(fetch_threat_detection_details),
    );
    if !filters.is_empty() {
        variables.insert("filterBy".to_string(), Value::Object(filters));
    }
    if let Some(after) = after {
        variables.insert("after".to_string(), Value::String(after.to_string()));
    }
    Ok(Value::Object(variables))
}

pub async fn fetch_connection(
    client: &WizClient,
    filters: Map<String, Value>,
    number: usize,
    all: bool,
    fetch_threat_detection_details: bool,
) -> Result<Value, String> {
    if !all && number == 0 {
        return Ok(json!({
            "nodes": [],
            "pageInfo": { "hasNextPage": false, "endCursor": null },
            "totalCount": 0
        }));
    }

    let mut nodes = Vec::new();
    let mut after: Option<String> = None;
    let mut total_count = Value::Null;
    let mut last_page_info = json!({ "hasNextPage": false, "endCursor": null });

    loop {
        let remaining = if all {
            500
        } else {
            number.saturating_sub(nodes.len()).min(500)
        };
        if remaining == 0 {
            break;
        }
        let variables = build_variables(
            filters.clone(),
            remaining,
            after.as_deref(),
            fetch_threat_detection_details,
        )?;
        let response = client.graphql(ISSUES_QUERY, variables).await?;
        let connection = response
            .pointer("/data/issues")
            .ok_or("Wiz response is missing data.issues")?;
        let page_nodes = connection
            .get("nodes")
            .and_then(Value::as_array)
            .ok_or("Wiz response is missing data.issues.nodes")?;
        nodes.extend(page_nodes.iter().cloned());
        total_count = connection.get("totalCount").cloned().unwrap_or(Value::Null);
        last_page_info = connection
            .get("pageInfo")
            .cloned()
            .ok_or("Wiz response is missing data.issues.pageInfo")?;
        let has_next_page = last_page_info
            .get("hasNextPage")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        if !has_next_page || (!all && nodes.len() >= number) {
            break;
        }
        after = Some(
            last_page_info
                .get("endCursor")
                .and_then(Value::as_str)
                .ok_or("Wiz response has no endCursor for the next page")?
                .to_string(),
        );
    }

    Ok(json!({
        "nodes": nodes,
        "pageInfo": last_page_info,
        "totalCount": total_count
    }))
}

pub async fn fetch_one(
    client: &WizClient,
    id: &str,
    fetch_threat_detection_details: bool,
) -> Result<Value, String> {
    let filters = Map::from_iter([("id".to_string(), json!([id]))]);
    let variables = build_variables(filters, 1, None, fetch_threat_detection_details)?;
    let response = client.graphql(ISSUES_QUERY, variables).await?;
    response
        .pointer("/data/issues/nodes/0")
        .cloned()
        .ok_or_else(|| format!("issue '{id}' was not found"))
}

pub async fn fetch_types(client: &WizClient, ids: &[String]) -> Result<Vec<Value>, String> {
    let filters = Map::from_iter([("id".to_string(), json!(ids))]);
    let variables = build_variables(filters, ids.len(), None, false)?;
    let response = client.graphql(ISSUES_QUERY, variables).await?;
    response
        .pointer("/data/issues/nodes")
        .and_then(Value::as_array)
        .cloned()
        .ok_or_else(|| "Wiz response is missing data.issues.nodes".to_string())
}

pub fn pin_threat_filter(args: &IssueFilterArgs, now: i64) -> Result<Map<String, Value>, String> {
    if args.r#type.is_some() {
        return Err(
            "--type cannot be used with threats; type is fixed to THREAT_DETECTION".to_string(),
        );
    }
    let mut filters = build_filters(args, now)?;
    filters.insert("type".to_string(), json!(["THREAT_DETECTION"]));
    Ok(filters)
}

fn insert_string(filters: &mut Map<String, Value>, key: &str, value: Option<&str>) {
    if let Some(value) = value {
        filters.insert(key.to_string(), Value::String(value.to_string()));
    }
}

fn insert_list(filters: &mut Map<String, Value>, key: &str, value: Option<&Vec<String>>) {
    if let Some(values) = value {
        if !values.is_empty() {
            filters.insert(key.to_string(), json!(values));
        }
    }
}

fn insert_enum_list(
    filters: &mut Map<String, Value>,
    key: &str,
    values: Option<&Vec<String>>,
    valid: &[&str],
) -> Result<(), String> {
    let Some(values) = values else {
        return Ok(());
    };
    let normalized = values
        .iter()
        .map(|value| validate_enum(key, value, valid))
        .collect::<Result<Vec<_>, _>>()?;
    if !normalized.is_empty() {
        filters.insert(key.to_string(), json!(normalized));
    }
    Ok(())
}

fn validate_enum(field: &str, value: &str, valid: &[&str]) -> Result<String, String> {
    let normalized = value.to_ascii_uppercase();
    if valid.contains(&normalized.as_str()) {
        Ok(normalized)
    } else {
        Err(format!(
            "invalid {field} '{value}'; valid values: {}",
            valid.join(", ")
        ))
    }
}

fn insert_date_range(
    filters: &mut Map<String, Value>,
    field: &str,
    after: Option<&str>,
    before: Option<&str>,
    now: i64,
) -> Result<(), String> {
    let mut range = Map::new();
    if let Some(duration) = after {
        range.insert(
            "after".to_string(),
            Value::String(relative_timestamp(now, duration)?),
        );
    }
    if let Some(duration) = before {
        range.insert(
            "before".to_string(),
            Value::String(relative_timestamp(now, duration)?),
        );
    }
    if !range.is_empty() {
        filters.insert(field.to_string(), Value::Object(range));
    }
    Ok(())
}

fn relative_timestamp(now: i64, duration: &str) -> Result<String, String> {
    let seconds = parse_duration(duration)?;
    let timestamp = now
        .checked_sub(seconds)
        .ok_or_else(|| format!("duration '{duration}' is too large"))?;
    Ok(format_timestamp(timestamp))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_uppercase_severity_filter() {
        let args = IssueFilterArgs {
            severity: Some(vec!["critical".to_string()]),
            ..Default::default()
        };
        let filters = build_filters(&args, 1_700_000_000).expect("valid filters");
        assert_eq!(filters.get("severity"), Some(&json!(["CRITICAL"])));
    }

    #[test]
    fn builds_multi_element_repeated_and_comma_filter() {
        let args = IssueFilterArgs {
            status: Some(vec!["open".to_string(), "IN_PROGRESS".to_string()]),
            ..Default::default()
        };
        let filters = build_filters(&args, 1_700_000_000).expect("valid filters");
        assert_eq!(filters.get("status"), Some(&json!(["OPEN", "IN_PROGRESS"])));
    }

    #[test]
    fn omits_unsupplied_filters() {
        let filters =
            build_filters(&IssueFilterArgs::default(), 1_700_000_000).expect("valid filters");
        assert!(!filters.contains_key("severity"));
        assert!(!filters.contains_key("createdAt"));
        assert!(!filters.contains_key("hasNote"));
    }

    #[test]
    fn invalid_enum_names_valid_values() {
        let args = IssueFilterArgs {
            severity: Some(vec!["urgent".to_string()]),
            ..Default::default()
        };
        let error = build_filters(&args, 1_700_000_000).expect_err("invalid severity");
        assert!(error.contains("valid values: INFORMATIONAL, LOW, MEDIUM, HIGH, CRITICAL"));
    }

    #[test]
    fn threat_and_issue_variables_use_the_same_builder() {
        let args = IssueFilterArgs::default();
        let issue_filters = build_filters(&args, 1_700_000_000).expect("valid filters");
        let issue_variables = build_variables(issue_filters, 20, None, false).expect("variables");
        assert_eq!(issue_variables["fetchThreatDetectionDetails"], false);
        assert!(issue_variables.get("filterBy").is_none());

        let threat_filters = pin_threat_filter(&args, 1_700_000_000).expect("threat filters");
        let threat_variables = build_variables(threat_filters, 20, None, true).expect("variables");
        assert_eq!(threat_variables["fetchThreatDetectionDetails"], true);
        assert_eq!(
            threat_variables["filterBy"]["type"],
            json!(["THREAT_DETECTION"])
        );
    }
}
