use std::fmt;

use rustler::{Atom, Decoder, Encoder, Env, NifResult, Term};

use crate::atoms;

/// Verdict enum matching sigil-protocol's Verdict.
/// Variants: Allowed, Blocked, Scanned.
#[derive(Debug, Clone, Copy)]
pub enum Verdict {
    Allowed,
    Blocked,
    Scanned,
}

impl Verdict {
    pub fn to_string_capitalized(self) -> &'static str {
        match self {
            Verdict::Allowed => "Allowed",
            Verdict::Blocked => "Blocked",
            Verdict::Scanned => "Scanned",
        }
    }

    pub fn from_atom(atom: Atom) -> Option<Verdict> {
        if atom == atoms::allowed() {
            Some(Verdict::Allowed)
        } else if atom == atoms::blocked() {
            Some(Verdict::Blocked)
        } else if atom == atoms::scanned() {
            Some(Verdict::Scanned)
        } else {
            None
        }
    }

    /// Convert to sigil-protocol crate Verdict.
    pub fn to_proto(self) -> sigil_protocol::Verdict {
        match self {
            Verdict::Allowed => sigil_protocol::Verdict::Allowed,
            Verdict::Blocked => sigil_protocol::Verdict::Blocked,
            Verdict::Scanned => sigil_protocol::Verdict::Scanned,
        }
    }
}

impl<'a> Decoder<'a> for Verdict {
    fn decode(term: Term<'a>) -> NifResult<Self> {
        let atom: Atom = term.decode()?;
        Verdict::from_atom(atom).ok_or(rustler::Error::BadArg)
    }
}

impl Encoder for Verdict {
    fn encode<'a>(&self, env: Env<'a>) -> Term<'a> {
        match self {
            Verdict::Allowed => atoms::allowed().encode(env),
            Verdict::Blocked => atoms::blocked().encode(env),
            Verdict::Scanned => atoms::scanned().encode(env),
        }
    }
}

/// Trust level enum matching sigil-protocol's TrustLevel (3 levels).
/// Low < Medium < High.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum TrustLevel {
    Low,
    Medium,
    High,
}

impl<'a> Decoder<'a> for TrustLevel {
    fn decode(term: Term<'a>) -> NifResult<Self> {
        let atom: Atom = term.decode()?;
        if atom == atoms::low() {
            Ok(TrustLevel::Low)
        } else if atom == atoms::medium() {
            Ok(TrustLevel::Medium)
        } else if atom == atoms::high() {
            Ok(TrustLevel::High)
        } else {
            Err(rustler::Error::BadArg)
        }
    }
}

impl Encoder for TrustLevel {
    fn encode<'a>(&self, env: Env<'a>) -> Term<'a> {
        match self {
            TrustLevel::Low => atoms::low().encode(env),
            TrustLevel::Medium => atoms::medium().encode(env),
            TrustLevel::High => atoms::high().encode(env),
        }
    }
}

impl fmt::Display for TrustLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TrustLevel::Low => write!(f, "low"),
            TrustLevel::Medium => write!(f, "medium"),
            TrustLevel::High => write!(f, "high"),
        }
    }
}

/// Risk level enum matching sigil-protocol's RiskLevel (3 levels).
/// Low < Medium < High.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RiskLevel {
    Low,
    Medium,
    High,
}

impl RiskLevel {
    /// Map risk level to required trust level.
    /// Matches sigil-protocol: Low→Low, Medium→Medium, High→High.
    pub fn required_trust(&self) -> TrustLevel {
        match self {
            RiskLevel::Low => TrustLevel::Low,
            RiskLevel::Medium => TrustLevel::Medium,
            RiskLevel::High => TrustLevel::High,
        }
    }
}

impl<'a> Decoder<'a> for RiskLevel {
    fn decode(term: Term<'a>) -> NifResult<Self> {
        let atom: Atom = term.decode()?;
        if atom == atoms::low() {
            Ok(RiskLevel::Low)
        } else if atom == atoms::medium() {
            Ok(RiskLevel::Medium)
        } else if atom == atoms::high() {
            Ok(RiskLevel::High)
        } else {
            Err(rustler::Error::BadArg)
        }
    }
}

impl Encoder for RiskLevel {
    fn encode<'a>(&self, env: Env<'a>) -> Term<'a> {
        match self {
            RiskLevel::Low => atoms::low().encode(env),
            RiskLevel::Medium => atoms::medium().encode(env),
            RiskLevel::High => atoms::high().encode(env),
        }
    }
}

impl fmt::Display for RiskLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RiskLevel::Low => write!(f, "low"),
            RiskLevel::Medium => write!(f, "medium"),
            RiskLevel::High => write!(f, "high"),
        }
    }
}

/// Scan hit structure matching Elixir map.
/// This is a SigilGuard extension — sigil-protocol's SensitivityScanner
/// only returns Option<String> (category name), not detailed hit info.
#[derive(Debug, Clone)]
pub struct ScanHit {
    pub name: String,
    pub category: String,
    pub severity: RiskLevel,
    pub match_text: String,
    pub offset: usize,
    pub length: usize,
    pub replacement_hint: Option<String>,
}

impl Encoder for ScanHit {
    fn encode<'a>(&self, env: Env<'a>) -> Term<'a> {
        let mut map = Term::map_new(env);
        map = map
            .map_put(
                rustler::types::atom::Atom::from_str(env, "name")
                    .unwrap()
                    .encode(env),
                self.name.encode(env),
            )
            .unwrap();
        map = map
            .map_put(
                rustler::types::atom::Atom::from_str(env, "category")
                    .unwrap()
                    .encode(env),
                self.category.encode(env),
            )
            .unwrap();
        map = map
            .map_put(
                rustler::types::atom::Atom::from_str(env, "severity")
                    .unwrap()
                    .encode(env),
                self.severity.encode(env),
            )
            .unwrap();
        map = map
            .map_put(
                rustler::types::atom::Atom::from_str(env, "match")
                    .unwrap()
                    .encode(env),
                self.match_text.encode(env),
            )
            .unwrap();
        map = map
            .map_put(
                rustler::types::atom::Atom::from_str(env, "offset")
                    .unwrap()
                    .encode(env),
                self.offset.encode(env),
            )
            .unwrap();
        map = map
            .map_put(
                rustler::types::atom::Atom::from_str(env, "length")
                    .unwrap()
                    .encode(env),
                self.length.encode(env),
            )
            .unwrap();
        map = map
            .map_put(
                rustler::types::atom::Atom::from_str(env, "replacement_hint")
                    .unwrap()
                    .encode(env),
                self.replacement_hint.encode(env),
            )
            .unwrap();
        map
    }
}
