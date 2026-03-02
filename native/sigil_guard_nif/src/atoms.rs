rustler::atoms! {
    ok,
    error,
    hit,
    // Verdicts
    allowed,
    blocked,
    scanned,
    confirm,
    // Trust levels
    anonymous,
    authenticated,
    verified,
    sovereign,
    // Risk levels
    none,
    low,
    medium,
    high,
    critical,
    // Error reasons
    broken,
    invalid_signature,
    invalid_base64,
    nif_not_loaded,
    // Audit
    genesis,
}
