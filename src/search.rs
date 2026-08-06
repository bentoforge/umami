//! In-memory search for the admin list endpoints.
//!
//! At the target scale (< ~10k tenants, 1–10 users/tenant) the list endpoints read all rows via
//! their GSI and filter here — DynamoDB can't express a case-insensitive multi-term substring match
//! as a key condition, and `FilterExpression`'s `contains()` is case-sensitive. Cheap and flexible
//! at this scale; revisit if row counts ever grow by orders of magnitude.

use serde_json::Value;

/// True if **every** whitespace-separated term in `query` is a case-insensitive substring of
/// `haystack`. An empty / whitespace-only query matches everything (no filtering).
pub fn query_matches(haystack: &str, query: &str) -> bool {
    let hay = haystack.to_lowercase();
    query
        .split_whitespace()
        .all(|term| hay.contains(&term.to_lowercase()))
}

/// Renders a custom-field JSON value as plain search text (strings verbatim, anything else as JSON).
pub fn value_search_text(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        other => other.to_string(),
    }
}
