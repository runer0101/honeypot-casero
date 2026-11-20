//! Homemade honeypot for authorized labs.
//!
//! Two traps that look attractive to an attacker and record everything they try:
//!
//! - a plaintext service that imitates an SSH login (banner, user, password and a fake
//!   shell). It is an **emulation**, not a real SSH server.
//! - a fake web login that records the submitted credentials and never authenticates
//!   anything.
//!
//! Everything happens on the loopback interface: the traps refuse to bind any other
//! address, and the log records what the attacker did in an authorized lab.

pub mod attack;
pub mod log;
pub mod shell;
pub mod trap;
pub mod viewer;

pub use log::{Event, EventLog};
