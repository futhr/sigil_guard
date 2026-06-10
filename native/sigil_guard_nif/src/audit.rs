use hmac::{Hmac, Mac};
use rustler::{Encoder, Env, NifResult, Term};
use sha2::Sha256;

use crate::atoms;

type HmacSha256 = Hmac<Sha256>;

const GENESIS_MARKER: &str = "genesis";

/// Sign an audit event with HMAC-SHA256, linking to previous event.
#[rustler::nif]
fn audit_sign_event<'a>(
    env: Env<'a>,
    event: Term<'a>,
    key: rustler::Binary<'a>,
    prev_hmac: Term<'a>,
) -> NifResult<Term<'a>> {
    // Get canonical bytes from event
    let canonical = event_canonical_bytes(env, event)?;

    // Get chain input
    let chain_input: String = if prev_hmac.is_atom() {
        // nil atom
        GENESIS_MARKER.to_string()
    } else {
        match prev_hmac.decode::<String>() {
            Ok(s) => s,
            Err(_) => GENESIS_MARKER.to_string(),
        }
    };

    // Compute HMAC
    let mut mac = HmacSha256::new_from_slice(key.as_slice()).map_err(|_| rustler::Error::BadArg)?;
    mac.update(canonical.as_bytes());
    mac.update(chain_input.as_bytes());
    let hmac_hex = hex_encode(mac.finalize().into_bytes().as_slice());

    // Return updated event map with hmac and prev_hmac fields
    let hmac_atom = rustler::types::atom::Atom::from_str(env, "hmac").unwrap();
    let prev_hmac_atom = rustler::types::atom::Atom::from_str(env, "prev_hmac").unwrap();

    let mut result = event;
    result = result
        .map_put(hmac_atom.encode(env), hmac_hex.encode(env))
        .map_err(|_| rustler::Error::BadArg)?;
    result = result
        .map_put(prev_hmac_atom.encode(env), prev_hmac)
        .map_err(|_| rustler::Error::BadArg)?;

    Ok(result)
}

/// Verify the integrity of an audit event chain.
///
/// Enforces contiguity — each event's `prev_hmac` must equal the actual
/// predecessor's `hmac` (`nil` for the first event) — before checking
/// the recomputed HMAC, matching the Elixir backend's `verify_chain/3`.
#[rustler::nif]
fn audit_verify_chain<'a>(
    env: Env<'a>,
    events: Vec<Term<'a>>,
    key: rustler::Binary<'a>,
) -> NifResult<Term<'a>> {
    let mut expected_prev: Option<String> = None;

    for (index, event) in events.iter().enumerate() {
        let canonical = event_canonical_bytes(env, *event)?;

        // The event's claimed predecessor link (nil atom → None)
        let prev_hmac_atom = rustler::types::atom::Atom::from_str(env, "prev_hmac").unwrap();
        let claimed_prev: Option<String> = match event.map_get(prev_hmac_atom.encode(env)) {
            Ok(term) => {
                if term.is_atom() {
                    None
                } else {
                    term.decode::<String>().ok()
                }
            }
            Err(_) => None,
        };

        if claimed_prev != expected_prev {
            return Ok((atoms::broken(), index).encode(env));
        }

        // Compute expected HMAC from the verified predecessor link
        let chain_input = expected_prev.as_deref().unwrap_or(GENESIS_MARKER);
        let mut mac =
            HmacSha256::new_from_slice(key.as_slice()).map_err(|_| rustler::Error::BadArg)?;
        mac.update(canonical.as_bytes());
        mac.update(chain_input.as_bytes());
        let expected = hex_encode(mac.finalize().into_bytes().as_slice());

        // Get actual HMAC from event (missing/non-string → broken, not a raise)
        let hmac_atom = rustler::types::atom::Atom::from_str(env, "hmac").unwrap();
        let actual: Option<String> = match event.map_get(hmac_atom.encode(env)) {
            Ok(term) => term.decode::<String>().ok(),
            Err(_) => None,
        };

        match actual {
            Some(actual) if secure_eq(&expected, &actual) => expected_prev = Some(actual),
            _ => return Ok((atoms::broken(), index).encode(env)),
        }
    }

    Ok(atoms::ok().encode(env))
}

/// Constant-time comparison — mirrors the Elixir backend's secure_compare
/// so HMAC verification does not leak matching-prefix length via timing.
fn secure_eq(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }

    a.bytes()
        .zip(b.bytes())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}

/// Build canonical bytes from an audit event struct.
/// Keys in lexicographic order: action, actor, id, result, timestamp, type
fn event_canonical_bytes(env: Env<'_>, event: Term<'_>) -> NifResult<String> {
    let action_atom = rustler::types::atom::Atom::from_str(env, "action").unwrap();
    let actor_atom = rustler::types::atom::Atom::from_str(env, "actor").unwrap();
    let id_atom = rustler::types::atom::Atom::from_str(env, "id").unwrap();
    let result_atom = rustler::types::atom::Atom::from_str(env, "result").unwrap();
    let timestamp_atom = rustler::types::atom::Atom::from_str(env, "timestamp").unwrap();
    let type_atom = rustler::types::atom::Atom::from_str(env, "type").unwrap();

    let action: String = event.map_get(action_atom.encode(env))?.decode()?;
    let actor: String = event.map_get(actor_atom.encode(env))?.decode()?;
    let id: String = event.map_get(id_atom.encode(env))?.decode()?;
    let result: String = event.map_get(result_atom.encode(env))?.decode()?;
    let timestamp: String = event.map_get(timestamp_atom.encode(env))?.decode()?;
    let event_type: String = event.map_get(type_atom.encode(env))?.decode()?;

    Ok(format!(
        r#"{{"action":{},"actor":{},"id":{},"result":{},"timestamp":{},"type":{}}}"#,
        serde_json::to_string(&action).unwrap(),
        serde_json::to_string(&actor).unwrap(),
        serde_json::to_string(&id).unwrap(),
        serde_json::to_string(&result).unwrap(),
        serde_json::to_string(&timestamp).unwrap(),
        serde_json::to_string(&event_type).unwrap(),
    ))
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}
