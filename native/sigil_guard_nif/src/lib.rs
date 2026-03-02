//! SigilGuard NIF - Rust NIF for SIGIL Protocol operations
//!
//! This NIF wraps core SIGIL protocol operations for performance and
//! protocol parity with the Rust reference implementation.
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
