use std::fmt;

use rustler::{Atom, Decoder, Encoder, Env, NifResult, Term};

use crate::atoms;

/// Verdict enum matching Elixir atoms
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

/// Trust level enum matching Elixir atoms
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum TrustLevel {
    Anonymous,
    Authenticated,
    Verified,
    Sovereign,
}

impl<'a> Decoder<'a> for TrustLevel {
    fn decode(term: Term<'a>) -> NifResult<Self> {
        let atom: Atom = term.decode()?;
        if atom == atoms::anonymous() {
            Ok(TrustLevel::Anonymous)
        } else if atom == atoms::authenticated() {
            Ok(TrustLevel::Authenticated)
        } else if atom == atoms::verified() {
            Ok(TrustLevel::Verified)
        } else if atom == atoms::sovereign() {
            Ok(TrustLevel::Sovereign)
        } else {
            Err(rustler::Error::BadArg)
        }
    }
}

impl Encoder for TrustLevel {
    fn encode<'a>(&self, env: Env<'a>) -> Term<'a> {
        match self {
            TrustLevel::Anonymous => atoms::anonymous().encode(env),
            TrustLevel::Authenticated => atoms::authenticated().encode(env),
            TrustLevel::Verified => atoms::verified().encode(env),
            TrustLevel::Sovereign => atoms::sovereign().encode(env),
        }
    }
}

impl fmt::Display for TrustLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TrustLevel::Anonymous => write!(f, "anonymous"),
            TrustLevel::Authenticated => write!(f, "authenticated"),
            TrustLevel::Verified => write!(f, "verified"),
            TrustLevel::Sovereign => write!(f, "sovereign"),
        }
    }
}

/// Risk level enum matching Elixir atoms
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RiskLevel {
    None,
    Low,
    Medium,
    High,
    Critical,
}

impl RiskLevel {
    pub fn required_trust(&self) -> TrustLevel {
        match self {
            RiskLevel::None | RiskLevel::Low => TrustLevel::Anonymous,
            RiskLevel::Medium => TrustLevel::Authenticated,
            RiskLevel::High => TrustLevel::Verified,
            RiskLevel::Critical => TrustLevel::Sovereign,
        }
    }
}

impl<'a> Decoder<'a> for RiskLevel {
    fn decode(term: Term<'a>) -> NifResult<Self> {
        let atom: Atom = term.decode()?;
        if atom == atoms::none() {
            Ok(RiskLevel::None)
        } else if atom == atoms::low() {
            Ok(RiskLevel::Low)
        } else if atom == atoms::medium() {
            Ok(RiskLevel::Medium)
        } else if atom == atoms::high() {
            Ok(RiskLevel::High)
        } else if atom == atoms::critical() {
            Ok(RiskLevel::Critical)
        } else {
            Err(rustler::Error::BadArg)
        }
    }
}

impl Encoder for RiskLevel {
    fn encode<'a>(&self, env: Env<'a>) -> Term<'a> {
        match self {
            RiskLevel::None => atoms::none().encode(env),
            RiskLevel::Low => atoms::low().encode(env),
            RiskLevel::Medium => atoms::medium().encode(env),
            RiskLevel::High => atoms::high().encode(env),
            RiskLevel::Critical => atoms::critical().encode(env),
        }
    }
}

impl fmt::Display for RiskLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RiskLevel::None => write!(f, "none"),
            RiskLevel::Low => write!(f, "low"),
            RiskLevel::Medium => write!(f, "medium"),
            RiskLevel::High => write!(f, "high"),
            RiskLevel::Critical => write!(f, "critical"),
        }
    }
}

/// Scan hit structure matching Elixir map
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
