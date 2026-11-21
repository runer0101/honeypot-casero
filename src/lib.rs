//! Trampa casera para laboratorios autorizados.
//!
//! Dos trampas que resultan atractivas para un atacante y que registran todo lo que intenta:
//!
//! - un servicio en texto plano que imita un acceso SSH (banner, usuario, contraseña y un
//!   shell falso). Es una **emulación**, no un servidor SSH real.
//! - un acceso web falso que anota las credenciales enviadas y no autentica a nadie.
//!
//! Todo ocurre en la interfaz de loopback: las trampas se niegan a escuchar en cualquier
//! otra dirección, y el registro anota lo que hizo el atacante en un laboratorio autorizado.

pub mod attack;
pub mod log;
pub mod shell;
pub mod trap;
pub mod viewer;

pub use log::{Event, EventLog};
