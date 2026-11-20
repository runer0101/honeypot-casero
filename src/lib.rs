//! Homemade honeypot for authorized labs.
//!
//! A trap that looks attractive to an attacker and records everything they try: a
//! plaintext service that imitates an SSH login (banner, user, password and a fake
//! shell). It is an **emulation**, not a real SSH server.
//!
//! Everything happens on the loopback interface: the traps refuse to bind any other
//! address, and the log records what the attacker did in an authorized lab.

pub mod log;
pub mod shell;
pub mod trap;

pub use log::{Event, EventLog};
