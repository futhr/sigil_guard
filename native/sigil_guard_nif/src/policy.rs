use rustler::{Encoder, Env, NifResult, Term};

use crate::atoms;
use crate::types::{RiskLevel, TrustLevel};

/// Risk classification by action prefix, matching Elixir implementation.
const PREFIX_RISK_MAPPINGS: &[(&str, RiskLevel)] = &[
    ("delete_", RiskLevel::Critical),
    ("drop_", RiskLevel::Critical),
    ("destroy_", RiskLevel::Critical),
    ("write_", RiskLevel::High),
    ("update_", RiskLevel::High),
    ("execute_", RiskLevel::High),
    ("run_", RiskLevel::High),
    ("create_", RiskLevel::Medium),
    ("modify_", RiskLevel::Medium),
    ("send_", RiskLevel::Medium),
    ("read_", RiskLevel::Low),
    ("get_", RiskLevel::Low),
    ("list_", RiskLevel::Low),
    ("search_", RiskLevel::Low),
];

#[rustler::nif]
fn classify_risk<'a>(env: Env<'a>, action: String, _opts: Term<'a>) -> NifResult<Term<'a>> {
    let risk = classify_by_prefix(&action);
    Ok(risk.encode(env))
}

#[rustler::nif]
fn evaluate_policy<'a>(
    env: Env<'a>,
    action: String,
    trust_level: TrustLevel,
    _opts: Term<'a>,
) -> NifResult<Term<'a>> {
    let risk = classify_by_prefix(&action);
    let required = risk.required_trust();

    if trust_level >= required {
        Ok(atoms::allowed().encode(env))
    } else if one_level_below(trust_level, required) {
        let reason = format!(
            "Action '{}' (risk: {}) requires {} trust, but caller has {}. Manual confirmation allowed.",
            action, risk, required, trust_level
        );
        Ok((atoms::confirm(), reason).encode(env))
    } else {
        Ok(atoms::blocked().encode(env))
    }
}

fn classify_by_prefix(action: &str) -> RiskLevel {
    for (prefix, level) in PREFIX_RISK_MAPPINGS {
        if action.starts_with(prefix) {
            return *level;
        }
    }
    RiskLevel::Medium
}

fn one_level_below(actual: TrustLevel, required: TrustLevel) -> bool {
    let levels = [
        TrustLevel::Anonymous,
        TrustLevel::Authenticated,
        TrustLevel::Verified,
        TrustLevel::Sovereign,
    ];

    let actual_idx = levels.iter().position(|l| *l == actual);
    let required_idx = levels.iter().position(|l| *l == required);

    match (actual_idx, required_idx) {
        (Some(a), Some(r)) => r.saturating_sub(a) == 1,
        _ => false,
    }
}
