//! Redaction of credential-shaped tokens.
//!
//! The proxy holds backend Tavily keys that the client is never supposed to
//! see. Anything derived from an upstream response — error bodies, parse
//! errors, log lines — can in principle echo the credential back, so it is
//! scrubbed on the way out.

/// Token prefixes known to identify credentials: Tavily's own (`tvly-`,
/// including `tvly-dev-`), this proxy's keys (`tp-`), and the `sk-` style that
/// OpenAI-compatible chat services hand out.
const SECRET_PREFIXES: [&str; 4] = ["tvly-", "tp-", "sk-", "jev-"];

/// Shortest token body worth hiding; keeps the redactor from mangling ordinary
/// hyphenated prose such as `tp-link` or `output-`.
const MIN_BODY_LEN: usize = 8;

/// Replace credential-shaped tokens with `<prefix>***`.
pub fn redact_secrets(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = String::with_capacity(input.len());
    let mut i = 0;

    while i < bytes.len() {
        let matched = SECRET_PREFIXES.iter().find_map(|prefix| {
            let prefix_bytes = prefix.as_bytes();
            if bytes[i..].starts_with(prefix_bytes) && boundary_before(bytes, i) {
                Some(prefix_bytes.len())
            } else {
                None
            }
        });

        let Some(prefix_len) = matched else {
            push_char_at(input, i, &mut out);
            i += char_len_at(input, i);
            continue;
        };

        let mut end = i + prefix_len;
        while end < bytes.len() && is_token_byte(bytes[end]) {
            end += 1;
        }

        if end - i - prefix_len >= MIN_BODY_LEN {
            out.push_str(&input[i..i + prefix_len]);
            out.push_str("***");
            i = end;
        } else {
            out.push_str(&input[i..i + prefix_len]);
            i += prefix_len;
        }
    }

    out
}

/// Replace every occurrence of a known secret value.
///
/// The prefix heuristic can only guess at a vendor's format. Values read from the
/// configuration are known exactly, so they are removed verbatim — longest first,
/// so a secret containing another is not left half-replaced.
pub fn redact_literals(input: &str, values: &[&str]) -> String {
    let mut secrets: Vec<&str> = values
        .iter()
        .copied()
        .filter(|value| value.len() >= MIN_BODY_LEN)
        .collect();
    secrets.sort_unstable_by_key(|secret| std::cmp::Reverse(secret.len()));

    let mut out = input.to_string();
    for secret in secrets {
        if out.contains(secret) {
            out = out.replace(secret, "***");
        }
    }
    out
}

/// Quoted values of credential-looking keys in a TOML document.
///
/// Needed where a parse error has to be scrubbed *before* the config could be
/// parsed: by definition the parsed values do not exist yet, so they are read off
/// the text by key name first.
pub fn literal_secrets_in_toml(text: &str) -> Vec<String> {
    const KEY_NAMES: [&str; 4] = ["key", "api_key", "tavily_key", "proxy_key"];

    text.lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.starts_with('#') || line.starts_with('[') {
                return None;
            }
            let (name, value) = line.split_once('=')?;
            let name = name.trim().trim_matches('"');
            if !KEY_NAMES.contains(&name) {
                return None;
            }
            quoted_value(value.trim()).map(str::to_string)
        })
        .collect()
}

/// The contents of a leading double-quoted string, if the value starts with one.
fn quoted_value(value: &str) -> Option<&str> {
    let rest = value.strip_prefix('"')?;
    let end = rest.find('"')?;
    let candidate = &rest[..end];
    (!candidate.is_empty()).then_some(candidate)
}

fn boundary_before(bytes: &[u8], index: usize) -> bool {
    match index.checked_sub(1).map(|prev| bytes[prev]) {
        None => true,
        Some(prev) => !prev.is_ascii_alphanumeric() && prev != b'_',
    }
}

fn is_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_'
}

fn char_len_at(input: &str, index: usize) -> usize {
    input[index..].chars().next().map_or(1, char::len_utf8)
}

fn push_char_at(input: &str, index: usize, out: &mut String) {
    if let Some(ch) = input[index..].chars().next() {
        out.push(ch);
    }
}
