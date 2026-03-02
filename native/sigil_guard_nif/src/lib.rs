//! SigilGuard NIF - Rust NIF for SIGIL Protocol operations
//!
//! Uses the `sigil-protocol` crate for type definitions and core operations
//! (envelope signing/verification, canonical bytes). Extends the protocol
//! with detailed scanning (offsets/hits) and HMAC-SHA256 audit chain.
//!
//! ## Safety
//!
//! NIFs run in the same OS process as the BEAM VM. A crash in the NIF
//! (segfault, panic, etc.) will crash the entire Erlang VM.
//!
//! Use the `:elixir` backend (default) unless you need NIF performance.

mod atoms;
mod audit;
mod envelope;
mod policy;
mod scanning;
mod types;

rustler::init!("Elixir.SigilGuard.Backend.NIF.Native");
