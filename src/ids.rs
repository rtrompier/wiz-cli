use std::io::{self, Read};

pub fn parse_ids_text(input: &str) -> Result<Vec<String>, String> {
    let ids: Vec<String> = input
        .split([',', '\n', '\r'])
        .map(str::trim)
        .filter(|id| !id.is_empty())
        .map(str::to_string)
        .collect();
    if ids.is_empty() {
        return Err("no issue IDs were provided".to_string());
    }
    Ok(ids)
}

pub fn read_ids(argument: &str) -> Result<Vec<String>, String> {
    if argument != "-" {
        return parse_ids_text(argument);
    }

    let mut input = String::new();
    io::stdin()
        .read_to_string(&mut input)
        .map_err(|e| format!("failed to read issue IDs from stdin: {e}"))?;
    parse_ids_text(&input).map_err(|_| "stdin did not contain any issue IDs".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_single_id() {
        assert_eq!(parse_ids_text("issue-1"), Ok(vec!["issue-1".to_string()]));
    }

    #[test]
    fn parses_comma_separated_ids_and_trims_whitespace() {
        assert_eq!(
            parse_ids_text(" issue-1, issue-2 ,issue-3 "),
            Ok(vec![
                "issue-1".to_string(),
                "issue-2".to_string(),
                "issue-3".to_string()
            ])
        );
    }

    #[test]
    fn skips_blank_lines() {
        assert_eq!(
            parse_ids_text("issue-1\n\n  \nissue-2\n"),
            Ok(vec!["issue-1".to_string(), "issue-2".to_string()])
        );
    }
}
