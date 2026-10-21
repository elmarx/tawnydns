//! Syntax of DNS names.

/// Lowercase labels like `www` or `a.b`, without trailing dot.
pub fn is_hostname(name: &str) -> bool {
    let valid_label = |label: &str| {
        !label.is_empty()
            && label.len() <= 63
            && label
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
    };
    name.len() <= 253 && name.split('.').all(valid_label)
}
