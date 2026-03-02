use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rustler::{Encoder, Env, NifResult, Term};

use crate::atoms;
use crate::types::Verdict;

/// Produce canonical bytes matching the Elixir implementation exactly.
///
/// Fields in lexicographic key order: identity, nonce, timestamp, verdict
/// Compact JSON, no whitespace, excluding signature and reason.
#[rustler::nif]
fn canonical_bytes<'a>(
    env: Env<'a>,
    identity: String,
    verdict: Verdict,
    timestamp: String,
    nonce_hex: String,
) -> NifResult<Term<'a>> {
    let verdict_str = verdict.to_string_capitalized();

    // Build canonical JSON with lexicographic key order
    let canonical = format!(
        r#"{{"identity":{},"nonce":{},"timestamp":{},"verdict":{}}}"#,
        serde_json::to_string(&identity).map_err(|_| rustler::Error::BadArg)?,
        serde_json::to_string(&nonce_hex).map_err(|_| rustler::Error::BadArg)?,
        serde_json::to_string(&timestamp).map_err(|_| rustler::Error::BadArg)?,
        serde_json::to_string(verdict_str).map_err(|_| rustler::Error::BadArg)?,
    );

    Ok(canonical.encode(env))
}

/// Sign an envelope with Ed25519.
///
/// Expects opts to contain a private_key binary (32-byte seed).
#[rustler::nif]
fn envelope_sign<'a>(
    env: Env<'a>,
    identity: String,
    verdict: Verdict,
    opts: Term<'a>,
) -> NifResult<Term<'a>> {
    // Extract private_key from opts keyword list
    let private_key_atom = rustler::types::atom::Atom::from_str(env, "private_key").unwrap();
    let private_key_b64u: String = opts.map_get(private_key_atom.encode(env))?.decode()?;

    let key_bytes = URL_SAFE_NO_PAD
        .decode(&private_key_b64u)
        .map_err(|_| rustler::Error::BadArg)?;

    if key_bytes.len() != 32 {
        return Err(rustler::Error::BadArg);
    }

    let signing_key = SigningKey::from_bytes(
        key_bytes
            .as_slice()
            .try_into()
            .map_err(|_| rustler::Error::BadArg)?,
    );
    let verifying_key = signing_key.verifying_key();

    // Extract optional fields
    let timestamp_atom = rustler::types::atom::Atom::from_str(env, "timestamp").unwrap();
    let timestamp: String = match opts.map_get(timestamp_atom.encode(env)) {
        Ok(term) => term.decode()?,
        Err(_) => generate_timestamp(),
    };

    let nonce_atom = rustler::types::atom::Atom::from_str(env, "nonce").unwrap();
    let nonce_hex: String = match opts.map_get(nonce_atom.encode(env)) {
        Ok(term) => term.decode()?,
        Err(_) => generate_nonce(),
    };

    let reason_atom = rustler::types::atom::Atom::from_str(env, "reason").unwrap();
    let reason: Option<String> = match opts.map_get(reason_atom.encode(env)) {
        Ok(term) => term.decode().ok(),
        Err(_) => None,
    };

    let verdict_str = verdict.to_string_capitalized();

    // Build canonical bytes
    let canonical = format!(
        r#"{{"identity":{},"nonce":{},"timestamp":{},"verdict":{}}}"#,
        serde_json::to_string(&identity).unwrap(),
        serde_json::to_string(&nonce_hex).unwrap(),
        serde_json::to_string(&timestamp).unwrap(),
        serde_json::to_string(verdict_str).unwrap(),
    );

    // Sign
    let signature = signing_key.sign(canonical.as_bytes());
    let signature_b64u = URL_SAFE_NO_PAD.encode(signature.to_bytes());

    // Build result map
    let mut map = Term::map_new(env);
    map = map
        .map_put("identity".encode(env), identity.encode(env))
        .unwrap();
    map = map
        .map_put("verdict".encode(env), verdict_str.encode(env))
        .unwrap();
    map = map
        .map_put("timestamp".encode(env), timestamp.encode(env))
        .unwrap();
    map = map
        .map_put("nonce".encode(env), nonce_hex.encode(env))
        .unwrap();
    map = map
        .map_put("signature".encode(env), signature_b64u.encode(env))
        .unwrap();

    if let Some(r) = reason {
        map = map.map_put("reason".encode(env), r.encode(env)).unwrap();
    }

    // Also include public key for verification
    let pub_key_b64u = URL_SAFE_NO_PAD.encode(verifying_key.as_bytes());
    map = map
        .map_put("public_key".encode(env), pub_key_b64u.encode(env))
        .unwrap();

    Ok(map)
}

/// Verify an envelope's Ed25519 signature.
#[rustler::nif]
fn envelope_verify<'a>(
    env: Env<'a>,
    envelope: Term<'a>,
    public_key_b64u: String,
) -> NifResult<Term<'a>> {
    // Decode public key
    let pub_bytes = match URL_SAFE_NO_PAD.decode(&public_key_b64u) {
        Ok(b) => b,
        Err(_) => return Ok((atoms::error(), atoms::invalid_base64()).encode(env)),
    };

    let verifying_key = match VerifyingKey::from_bytes(
        pub_bytes
            .as_slice()
            .try_into()
            .map_err(|_| rustler::Error::BadArg)?,
    ) {
        Ok(k) => k,
        Err(_) => return Ok((atoms::error(), atoms::invalid_base64()).encode(env)),
    };

    // Extract envelope fields
    let identity: String = envelope.map_get("identity".encode(env))?.decode()?;
    let verdict_str: String = envelope.map_get("verdict".encode(env))?.decode()?;
    let timestamp: String = envelope.map_get("timestamp".encode(env))?.decode()?;
    let nonce_hex: String = envelope.map_get("nonce".encode(env))?.decode()?;
    let signature_b64u: String = envelope.map_get("signature".encode(env))?.decode()?;

    // Decode signature
    let sig_bytes = match URL_SAFE_NO_PAD.decode(&signature_b64u) {
        Ok(b) => b,
        Err(_) => return Ok((atoms::error(), atoms::invalid_base64()).encode(env)),
    };

    let sig_array: &[u8; 64] = sig_bytes
        .as_slice()
        .try_into()
        .map_err(|_| rustler::Error::BadArg)?;
    let signature = Signature::from_bytes(sig_array);

    // Rebuild canonical bytes
    let canonical = format!(
        r#"{{"identity":{},"nonce":{},"timestamp":{},"verdict":{}}}"#,
        serde_json::to_string(&identity).unwrap(),
        serde_json::to_string(&nonce_hex).unwrap(),
        serde_json::to_string(&timestamp).unwrap(),
        serde_json::to_string(&verdict_str).unwrap(),
    );

    // Verify
    match verifying_key.verify(canonical.as_bytes(), &signature) {
        Ok(()) => Ok(atoms::ok().encode(env)),
        Err(_) => Ok((atoms::error(), atoms::invalid_signature()).encode(env)),
    }
}

fn generate_timestamp() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let dur = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
    let secs = dur.as_secs();
    let millis = dur.subsec_millis();

    // Convert to rough UTC datetime
    let days = secs / 86400;
    let rem = secs % 86400;
    let hours = rem / 3600;
    let minutes = (rem % 3600) / 60;
    let seconds = rem % 60;

    // Simple date calculation (good enough for timestamps)
    let (year, month, day) = days_to_ymd(days as i64);

    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
        year, month, day, hours, minutes, seconds, millis
    )
}

fn days_to_ymd(days: i64) -> (i64, u32, u32) {
    // Algorithm from http://howardhinnant.github.io/date_algorithms.html
    let z = days + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u32;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

fn generate_nonce() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex_encode(&bytes)
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}
