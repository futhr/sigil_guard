use regex::Regex;
use rustler::{Encoder, Env, NifResult, Term};

use crate::atoms;
use crate::types::{RiskLevel, ScanHit};

/// Built-in SIGIL patterns with sigil-protocol's 3-level RiskLevel severity.
struct Pattern {
    name: &'static str,
    category: &'static str,
    severity: RiskLevel,
    regex: Regex,
    replacement_hint: Option<&'static str>,
}

fn built_in_patterns() -> Vec<Pattern> {
    vec![
        Pattern {
            name: "aws_access_key",
            category: "credential",
            severity: RiskLevel::High,
            regex: Regex::new(r"(AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}").unwrap(),
            replacement_hint: Some("[AWS_KEY]"),
        },
        Pattern {
            name: "generic_api_key",
            category: "credential",
            severity: RiskLevel::High,
            regex: Regex::new(
                r#"(?i)(api[_-]?key|apikey)\s*[=:]\s*['"]?([a-zA-Z0-9_\-]{20,})['"]?"#,
            )
            .unwrap(),
            replacement_hint: Some("[API_KEY]"),
        },
        Pattern {
            name: "bearer_token",
            category: "credential",
            severity: RiskLevel::Medium,
            regex: Regex::new(r"Bearer\s+[a-zA-Z0-9_\-.]{20,}").unwrap(),
            replacement_hint: Some("[BEARER_TOKEN]"),
        },
        Pattern {
            name: "database_uri",
            category: "connection_string",
            severity: RiskLevel::High,
            regex: Regex::new(r"(?i)(postgres|mysql|mongodb)://[^\s]+").unwrap(),
            replacement_hint: Some("[DATABASE_URI]"),
        },
        Pattern {
            name: "private_key",
            category: "cryptographic_key",
            severity: RiskLevel::High,
            regex: Regex::new(r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----").unwrap(),
            replacement_hint: Some("[PRIVATE_KEY]"),
        },
        Pattern {
            name: "generic_secret",
            category: "credential",
            severity: RiskLevel::Medium,
            regex: Regex::new(
                r#"(?i)(secret|password|passwd|token|credential)\s*[=:]\s*['"]?([^\s'"]{8,})['"]?"#,
            )
            .unwrap(),
            replacement_hint: Some("[SECRET]"),
        },
    ]
}

#[rustler::nif(schedule = "DirtyCpu")]
fn scan<'a>(env: Env<'a>, text: String, __opts: Term<'a>) -> NifResult<Term<'a>> {
    let patterns = built_in_patterns();
    let mut hits: Vec<ScanHit> = Vec::new();

    for pattern in &patterns {
        for mat in pattern.regex.find_iter(&text) {
            hits.push(ScanHit {
                name: pattern.name.to_string(),
                category: pattern.category.to_string(),
                severity: pattern.severity,
                match_text: mat.as_str().to_string(),
                offset: mat.start(),
                length: mat.len(),
                replacement_hint: pattern.replacement_hint.map(|s| s.to_string()),
            });
        }
    }

    hits.sort_by_key(|h| h.offset);

    if hits.is_empty() {
        Ok((atoms::ok(), text).encode(env))
    } else {
        Ok((atoms::hit(), hits).encode(env))
    }
}

#[rustler::nif(schedule = "DirtyCpu")]
fn redact<'a>(
    env: Env<'a>,
    text: String,
    hits: Vec<Term<'a>>,
    _opts: Term<'a>,
) -> NifResult<Term<'a>> {
    let default_replacement = "[REDACTED]";

    let mut replacements: Vec<(usize, usize, String)> = Vec::new();

    for hit_term in &hits {
        let offset: usize = hit_term
            .map_get(
                rustler::types::atom::Atom::from_str(env, "offset")
                    .unwrap()
                    .encode(env),
            )?
            .decode()?;

        let length: usize = hit_term
            .map_get(
                rustler::types::atom::Atom::from_str(env, "length")
                    .unwrap()
                    .encode(env),
            )?
            .decode()?;

        let hint: Option<String> = match hit_term.map_get(
            rustler::types::atom::Atom::from_str(env, "replacement_hint")
                .unwrap()
                .encode(env),
        ) {
            Ok(term) => term.decode().ok(),
            Err(_) => None,
        };

        let replacement = hint.unwrap_or_else(|| default_replacement.to_string());
        replacements.push((offset, length, replacement));
    }

    // Sort by offset descending to preserve positions
    replacements.sort_by(|a, b| b.0.cmp(&a.0));

    let mut result = text;
    for (offset, length, replacement) in replacements {
        if offset + length <= result.len() {
            result = format!(
                "{}{}{}",
                &result[..offset],
                replacement,
                &result[offset + length..]
            );
        }
    }

    Ok(result.encode(env))
}

#[rustler::nif(schedule = "DirtyCpu")]
fn scan_and_redact<'a>(env: Env<'a>, text: String, __opts: Term<'a>) -> NifResult<Term<'a>> {
    let patterns = built_in_patterns();
    let mut hits: Vec<(usize, usize, String)> = Vec::new();

    for pattern in &patterns {
        for mat in pattern.regex.find_iter(&text) {
            let replacement = pattern.replacement_hint.unwrap_or("[REDACTED]").to_string();
            hits.push((mat.start(), mat.len(), replacement));
        }
    }

    if hits.is_empty() {
        return Ok(text.encode(env));
    }

    // Sort by offset descending
    hits.sort_by(|a, b| b.0.cmp(&a.0));

    let mut result = text;
    for (offset, length, replacement) in hits {
        if offset + length <= result.len() {
            result = format!(
                "{}{}{}",
                &result[..offset],
                replacement,
                &result[offset + length..]
            );
        }
    }

    Ok(result.encode(env))
}
