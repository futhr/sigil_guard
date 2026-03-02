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
#[rustler::nif]
fn audit_verify_chain<'a>(
    env: Env<'a>,
    events: Vec<Term<'a>>,
    key: rustler::Binary<'a>,
) -> NifResult<Term<'a>> {
    for (index, event) in events.iter().enumerate() {
        let canonical = event_canonical_bytes(env, *event)?;

        // Get prev_hmac from event
        let prev_hmac_atom = rustler::types::atom::Atom::from_str(env, "prev_hmac").unwrap();
        let chain_input: String = match event.map_get(prev_hmac_atom.encode(env)) {
            Ok(term) => {
                if term.is_atom() {
                    GENESIS_MARKER.to_string()
                } else {
                    term.decode::<String>()
                        .unwrap_or_else(|_| GENESIS_MARKER.to_string())
                }
            }
            Err(_) => GENESIS_MARKER.to_string(),
        };

        // Compute expected HMAC
        let mut mac =
            HmacSha256::new_from_slice(key.as_slice()).map_err(|_| rustler::Error::BadArg)?;
        mac.update(canonical.as_bytes());
        mac.update(chain_input.as_bytes());
        let expected = hex_encode(mac.finalize().into_bytes().as_slice());

        // Get actual HMAC from event
        let hmac_atom = rustler::types::atom::Atom::from_str(env, "hmac").unwrap();
        let actual: String = event.map_get(hmac_atom.encode(env))?.decode()?;

        if expected != actual {
            return Ok((atoms::broken(), index).encode(env));
        }
    }

    Ok(atoms::ok().encode(env))
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
