use serde_json::Value;

pub fn print_output(value: &Value, human: bool) -> Result<(), String> {
    let output = if human {
        format_human(value)
    } else {
        serde_json::to_string(value).map_err(|e| e.to_string())?
    };
    println!("{output}");
    Ok(())
}

pub fn print_dry_run(operations: &[crate::commands::Operation], human: bool) -> Result<(), String> {
    if !human {
        let output = serde_json::to_string(operations).map_err(|e| e.to_string())?;
        println!("{output}");
        return Ok(());
    }

    for (index, operation) in operations.iter().enumerate() {
        if index > 0 {
            println!();
        }
        println!("Operation {}", index + 1);
        println!("Query:");
        println!("{}", operation.query);
        println!("Variables:");
        println!(
            "{}",
            serde_json::to_string_pretty(&operation.variables).map_err(|e| e.to_string())?
        );
    }
    Ok(())
}

fn format_human(value: &Value) -> String {
    if let Some(nodes) = value.get("nodes").and_then(Value::as_array) {
        if nodes.iter().any(|node| node.get("severity").is_some()) {
            return format_issues(nodes);
        }
        return format_nodes(nodes);
    }
    if let Some(items) = value.as_array() {
        return format_nodes(items);
    }
    if let Some(object) = value.as_object() {
        return format_object(object);
    }
    value_to_cell(value)
}

fn format_issues(nodes: &[Value]) -> String {
    let mut output = String::new();
    output.push_str(&format!(
        "{:<38} {:<24} {:<12} {:<14} {:<28} {}\n",
        "ID", "TYPE", "STATUS", "SEVERITY", "ENTITY", "UPDATED"
    ));
    output.push_str(&"-".repeat(135));
    output.push('\n');
    for node in nodes {
        let id = string_at(node, "id");
        let issue_type = string_at(node, "type");
        let status = string_at(node, "status");
        let severity = string_at(node, "severity");
        let entity = node
            .get("entity")
            .and_then(|entity| entity.get("name"))
            .and_then(Value::as_str)
            .unwrap_or("-");
        let updated = string_at(node, "updatedAt");
        output.push_str(&format!(
            "{:<38} {:<24} {:<12} {:<14} {:<28} {}\n",
            truncate(id, 38),
            truncate(issue_type, 24),
            truncate(status, 12),
            truncate(severity, 14),
            truncate(entity, 28),
            updated
        ));
    }
    output
}

fn format_nodes(nodes: &[Value]) -> String {
    if nodes.is_empty() {
        return "No results".to_string();
    }
    let mut output = String::new();
    output.push_str(&format!("{:<38} {:<24} {}\n", "ID", "OPERATION", "RESULT"));
    output.push_str(&"-".repeat(100));
    output.push('\n');
    for node in nodes {
        let id = node.get("id").and_then(Value::as_str).unwrap_or("-");
        let operation = node
            .get("operation")
            .and_then(Value::as_str)
            .or_else(|| node.get("timestamp").and_then(Value::as_str))
            .unwrap_or("-");
        let result = node
            .get("error")
            .map(value_to_cell)
            .or_else(|| node.get("success").map(value_to_cell))
            .unwrap_or_else(|| value_to_cell(node));
        output.push_str(&format!(
            "{:<38} {:<24} {}\n",
            truncate(id, 38),
            truncate(operation, 24),
            result
        ));
    }
    output
}

fn format_object(object: &serde_json::Map<String, Value>) -> String {
    let width = object.keys().map(String::len).max().unwrap_or(5).max(5);
    let mut output = String::new();
    output.push_str(&format!("{:<width$} VALUE\n", "FIELD"));
    output.push_str(&"-".repeat(width + 65));
    output.push('\n');
    for (key, value) in object {
        output.push_str(&format!(
            "{key:<width$} {}\n",
            value_to_cell(value).replace('\n', " ")
        ));
    }
    output
}

fn string_at<'a>(value: &'a Value, key: &str) -> &'a str {
    value.get(key).and_then(Value::as_str).unwrap_or("-")
}

fn value_to_cell(value: &Value) -> String {
    match value {
        Value::Null => "-".to_string(),
        Value::String(value) => value.clone(),
        Value::Bool(value) => value.to_string(),
        Value::Number(value) => value.to_string(),
        Value::Array(values) => values
            .iter()
            .map(value_to_cell)
            .collect::<Vec<_>>()
            .join(", "),
        Value::Object(_) => serde_json::to_string(value).unwrap_or_else(|_| "{...}".to_string()),
    }
}

fn truncate(value: &str, max: usize) -> String {
    if value.chars().count() <= max {
        value.to_string()
    } else {
        let prefix: String = value.chars().take(max.saturating_sub(3)).collect();
        format!("{prefix}...")
    }
}
