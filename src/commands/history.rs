use serde_json::{json, Value};

use crate::client::WizClient;
use crate::format::print_output;

const QUERY: &str = r#"query IssueHistoryEvents($filterBy: IssueHistoryEventFilters, $first: Int, $after: String) {
  issueHistoryEvents(filterBy: $filterBy, first: $first, after: $after) {
    nodes { id type timestamp message }
    pageInfo { hasNextPage endCursor }
    totalCount
  }
}"#;

pub async fn run(id: &str, human: bool) -> Result<(), String> {
    let client = WizClient::new().await?;
    let mut nodes = Vec::new();
    let mut after: Option<String> = None;
    let mut page_info = json!({ "hasNextPage": false, "endCursor": null });
    let mut total_count = None;

    loop {
        let mut variables = json!({ "filterBy": { "issue": id }, "first": 500 });
        if let Some(cursor) = &after {
            variables["after"] = json!(cursor);
        }
        let response = client.graphql(QUERY, variables).await?;
        let connection = response
            .pointer("/data/issueHistoryEvents")
            .ok_or("Wiz response is missing data.issueHistoryEvents")?;
        let page_nodes = connection
            .get("nodes")
            .and_then(Value::as_array)
            .ok_or("Wiz response is missing data.issueHistoryEvents.nodes")?;
        nodes.extend(page_nodes.iter().cloned());
        if total_count.is_none() {
            total_count = Some(connection.get("totalCount").cloned().unwrap_or(Value::Null));
        }
        page_info = connection
            .get("pageInfo")
            .cloned()
            .ok_or("Wiz response is missing data.issueHistoryEvents.pageInfo")?;
        if !page_info
            .get("hasNextPage")
            .and_then(Value::as_bool)
            .unwrap_or(false)
        {
            break;
        }
        after = Some(
            page_info
                .get("endCursor")
                .and_then(Value::as_str)
                .ok_or("Wiz response has no endCursor for the next history page")?
                .to_string(),
        );
    }

    print_output(
        &json!({ "nodes": nodes, "pageInfo": page_info, "totalCount": total_count.unwrap_or(Value::Null) }),
        human,
    )
}
