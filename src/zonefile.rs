//! Helpers for BIND zone-file import.

/// Make every record's TTL explicit using the active `$TTL`, so the parser
/// cannot fall back to "the previous record's TTL" (RFC 2308 §4 says `$TTL`
/// wins when present; hickory's parser inherits the last TTL instead).
pub fn make_ttls_explicit(text: &str, fallback_ttl: u32) -> String {
    const CLASSES: [&str; 4] = ["IN", "CH", "HS", "ANY"];
    let mut ttl = fallback_ttl.to_string();
    let mut out = String::with_capacity(text.len() + 64);
    let mut in_parens = false;
    for line in text.lines() {
        let code = line.split(';').next().unwrap_or("");
        if in_parens {
            out.push_str(line);
            out.push('\n');
            if code.contains(')') {
                in_parens = false;
            }
            continue;
        }
        let trimmed = code.trim_start();
        if trimmed.is_empty() || trimmed.starts_with('$') {
            if let Some(rest) = trimmed.strip_prefix("$TTL") {
                if let Some(v) = rest.split_whitespace().next() {
                    ttl = v.to_string();
                }
            }
            out.push_str(line);
            out.push('\n');
            continue;
        }
        let owner_omitted = line.starts_with(' ') || line.starts_with('\t');
        let tokens: Vec<&str> = code.split_whitespace().collect();
        // Fields after the owner: [ttl] [class] type ...
        let start = if owner_omitted { 0 } else { 1 };
        let has_ttl = tokens.get(start).map(|t| is_ttl(t)).unwrap_or(false);
        let has_class_first = tokens
            .get(start)
            .map(|t| CLASSES.contains(&t.to_ascii_uppercase().as_str()))
            .unwrap_or(false);
        let has_ttl_after_class =
            has_class_first && tokens.get(start + 1).map(|t| is_ttl(t)).unwrap_or(false);
        if !has_ttl && !has_ttl_after_class && tokens.len() > start {
            // Insert the TTL right after the owner (or at the start of the fields).
            let mut rebuilt = String::new();
            if owner_omitted {
                rebuilt.push('\t');
            } else {
                rebuilt.push_str(tokens[0]);
                rebuilt.push('\t');
            }
            rebuilt.push_str(&ttl);
            rebuilt.push('\t');
            rebuilt.push_str(&tokens[start..].join(" "));
            if let Some((_, comment)) = line.split_once(';') {
                rebuilt.push_str(" ;");
                rebuilt.push_str(comment);
            }
            out.push_str(&rebuilt);
        } else {
            out.push_str(line);
        }
        out.push('\n');
        if code.contains('(') && !code.contains(')') {
            in_parens = true;
        }
    }
    out
}

/// `300`, `1h`, `2d`, `1w3d` are TTLs; anything else is not.
fn is_ttl(t: &str) -> bool {
    !t.is_empty()
        && t.chars().all(|c| {
            c.is_ascii_digit() || matches!(c.to_ascii_lowercase(), 's' | 'm' | 'h' | 'd' | 'w')
        })
        && t.chars().next().unwrap().is_ascii_digit()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_ttls() {
        let input = "$ORIGIN example.test.\n$TTL 600\n@ IN SOA ns1 host (\n  1 2 3 4 5 )\n@ IN NS ns1\nweb 120 IN A 10.0.0.2\nweb IN AAAA ::1\n\tIN TXT \"same owner\" ; comment\n$TTL 1h\nmail IN 30 A 10.0.0.3\napi 2d A 10.0.0.4\n";
        let out = make_ttls_explicit(input, 300);
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines[2], "@\t600\tIN SOA ns1 host (");
        assert_eq!(lines[3], "  1 2 3 4 5 )");
        assert_eq!(lines[4], "@\t600\tIN NS ns1");
        assert_eq!(lines[5], "web 120 IN A 10.0.0.2");
        assert_eq!(lines[6], "web\t600\tIN AAAA ::1");
        assert_eq!(lines[7], "\t600\tIN TXT \"same owner\" ; comment");
        assert_eq!(lines[9], "mail IN 30 A 10.0.0.3");
        assert_eq!(lines[10], "api 2d A 10.0.0.4");
    }
}
