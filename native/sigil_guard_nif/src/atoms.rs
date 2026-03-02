rustler::atoms! {
    ok,
    error,
    hit,
    // Verdicts
    allowed,
    blocked,
    scanned,
    confirm,
    // Trust levels (matches sigil-protocol TrustLevel: Low, Medium, High)
    low,
    medium,
    high,
    // Error reasons
    broken,
    invalid_signature,
    invalid_base64,
    nif_not_loaded,
    // Audit
    genesis,
}
