use std::time::{SystemTime, UNIX_EPOCH};

pub fn unix_now() -> Result<i64, String> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| format!("system time is before the Unix epoch: {e}"))?;
    i64::try_from(duration.as_secs()).map_err(|_| "current Unix timestamp is too large".to_string())
}

pub fn parse_duration(input: &str) -> Result<i64, String> {
    let (number, unit) = input.split_at(input.len().saturating_sub(1));
    let value = number.parse::<i64>().map_err(|_| {
        format!("invalid duration '{input}'; use a positive value such as 30m, 12h, 7d, or 2w")
    })?;
    if value <= 0 {
        return Err(format!(
            "invalid duration '{input}'; use a positive value such as 30m, 12h, 7d, or 2w"
        ));
    }
    let multiplier = match unit {
        "m" => 60,
        "h" => 60 * 60,
        "d" => 24 * 60 * 60,
        "w" => 7 * 24 * 60 * 60,
        _ => {
            return Err(format!(
                "invalid duration '{input}'; use a positive value such as 30m, 12h, 7d, or 2w"
            ))
        }
    };
    value
        .checked_mul(multiplier)
        .ok_or_else(|| format!("duration '{input}' is too large"))
}

pub fn format_timestamp(timestamp: i64) -> String {
    let days = timestamp.div_euclid(86_400);
    let seconds = timestamp.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    let hour = seconds / 3_600;
    let minute = (seconds % 3_600) / 60;
    let second = seconds % 60;
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let shifted = days + 719_468;
    let era = if shifted >= 0 {
        shifted / 146_097
    } else {
        (shifted - 146_096) / 146_097
    };
    let day_of_era = shifted - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let mut year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };
    if month <= 2 {
        year += 1;
    }
    (year, month, day)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_known_timestamps() {
        assert_eq!(format_timestamp(0), "1970-01-01T00:00:00Z");
        assert_eq!(format_timestamp(1_700_000_000), "2023-11-14T22:13:20Z");
        assert_eq!(format_timestamp(1_709_164_800), "2024-02-29T00:00:00Z");
    }

    #[test]
    fn parses_supported_durations() {
        assert_eq!(parse_duration("30m"), Ok(1_800));
        assert_eq!(parse_duration("12h"), Ok(43_200));
        assert_eq!(parse_duration("7d"), Ok(604_800));
        assert_eq!(parse_duration("2w"), Ok(1_209_600));
    }

    #[test]
    fn rejects_malformed_duration() {
        assert!(parse_duration("one day").is_err());
    }
}
