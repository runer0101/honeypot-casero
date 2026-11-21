//! The traps: a plaintext SSH-like login service and a fake web login.

use crate::log::{Event, EventLog};
use crate::shell;
use std::io::{BufReader, ErrorKind, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Banner announced by the SSH-like trap.
pub const SSH_BANNER: &str = "SSH-2.0-OpenSSH_9.6 Ubuntu-3ubuntu13";

/// Prompt of the fake shell.
pub const SHELL_PROMPT: &str = "root@victima:~# ";

/// How many credentials are denied before the trap lets the attacker in.
pub const MAX_FAILED_ATTEMPTS: usize = 2;

/// Tope de credenciales aceptadas en una misma sesión.
///
/// Si el cliente insiste de más, la trampa lo echa y lo anota: así se distingue un
/// atacante real de un script mal configurado.
pub const MAX_INTENTOS: usize = 10;

/// Tiempo máximo de una sesión.
///
/// Si el atacante se queda quieto, la sesión se cierra sola: ningún hilo debe quedar
/// esperando para siempre.
pub const TIEMPO_MAXIMO_SESION: Duration = Duration::from_secs(300);

/// Maximum size accepted for an HTTP request head.
const MAX_HEAD_BYTES: usize = 8_192;

/// Maximum size accepted for an HTTP body.
const MAX_BODY_BYTES: usize = 4_096;

/// Maximum size accepted for one line of the fake shell.
///
/// A client that never sends a newline cannot make the string grow without limit.
const MAX_LINE_BYTES: usize = 8_192;

/// Message used when someone tries to bind outside the loopback.
const LOOPBACK_ONLY: &str = "el honeypot solo acepta direcciones de loopback (127.0.0.1 o ::1); \
este laboratorio es una actividad autorizada";

/// `true` for the loopback addresses the traps are allowed to bind.
pub fn is_loopback(address: &IpAddr) -> bool {
    address.is_loopback()
}

/// Starts the SSH-like trap on `bind` and returns the address actually bound.
pub fn start_ssh_trap(bind: SocketAddr, log: Arc<EventLog>) -> std::io::Result<SocketAddr> {
    // The guard lives here, not only in the CLI: anyone who uses the library is also
    // prevented from binding outside the loopback.
    if !is_loopback(&bind.ip()) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            LOOPBACK_ONLY,
        ));
    }
    let listener = TcpListener::bind(bind)?;
    let local = listener.local_addr()?;
    let sessions = Arc::new(AtomicU64::new(0));

    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let stream = match stream {
                Ok(stream) => stream,
                Err(_) => break,
            };
            let log = Arc::clone(&log);
            let sessions = Arc::clone(&sessions);
            std::thread::spawn(move || {
                let id = sessions.fetch_add(1, Ordering::Relaxed) + 1;
                serve_ssh_session(stream, &log, &format!("s-{id}"));
            });
        }
    });

    Ok(local)
}

/// Serves one SSH-like session: banner, credentials, then the fake shell.
pub fn serve_ssh_session(stream: TcpStream, log: &EventLog, session: &str) {
    serve_ssh_session_con_limites(stream, log, session, MAX_INTENTOS, TIEMPO_MAXIMO_SESION);
}

/// Igual que [`serve_ssh_session`], pero con el tope de intentos y el tiempo máximo
/// como parámetros: así las pruebas pueden usar valores pequeños.
pub fn serve_ssh_session_con_limites(
    stream: TcpStream,
    log: &EventLog,
    session: &str,
    max_intentos: usize,
    tiempo_maximo: Duration,
) {
    let peer = peer_address(&stream);
    let mut writer = match stream.try_clone() {
        Ok(writer) => writer,
        Err(_) => return,
    };
    let mut reader = BufReader::new(stream);
    let started = Instant::now();
    // Tope absoluto: por mucho que el atacante siga mandando bytes, la sesión se
    // cierra al cumplirse el plazo.
    let plazo = started + tiempo_maximo;
    // Si el atacante se queda callado, la sesión se cierra sola.
    let _ = reader.get_ref().set_read_timeout(Some(tiempo_maximo));
    // Y lo mismo al escribir: un cliente que abre y no lee no puede dejar el hilo
    // de la trampa bloqueado para siempre.
    let _ = reader.get_ref().set_write_timeout(Some(tiempo_maximo));

    let _ = log.append(&Event::new("ssh", "connect", &peer, session));
    if write!(writer, "{SSH_BANNER}\r\n").is_err() {
        return;
    }

    let mut failures = 0usize;
    let mut attempts = 0usize;
    loop {
        if Instant::now() >= plazo {
            let _ = log.append(&Event::new("ssh", "sesion_timeout", &peer, session));
            return;
        }
        if write!(writer, "login: ").is_err() {
            return;
        }
        let user = match read_line(&mut reader, plazo) {
            Lectura::Linea(user) => user,
            Lectura::Fin => return,
            Lectura::DemasiadoLarga => {
                let _ = log.append(&Event::new("ssh", "linea_demasiada_larga", &peer, session));
                return;
            }
            Lectura::TiempoAgotado => {
                let _ = log.append(&Event::new("ssh", "sesion_timeout", &peer, session));
                return;
            }
        };
        if write!(writer, "Password: ").is_err() {
            return;
        }
        let password = match read_line(&mut reader, plazo) {
            Lectura::Linea(password) => password,
            Lectura::Fin => return,
            Lectura::DemasiadoLarga => {
                let _ = log.append(&Event::new("ssh", "linea_demasiada_larga", &peer, session));
                return;
            }
            Lectura::TiempoAgotado => {
                let _ = log.append(&Event::new("ssh", "sesion_timeout", &peer, session));
                return;
            }
        };

        attempts += 1;
        if attempts > max_intentos {
            let _ = log.append(
                &Event::new("ssh", "limite_intentos", &peer, session)
                    .with("intentos", &attempts.to_string()),
            );
            let _ = write!(writer, "Too many authentication failures.\r\n");
            // La sesión se acaba aquí: el atacante ya no entra al shell.
            return;
        }

        if failures < MAX_FAILED_ATTEMPTS {
            failures += 1;
            let _ = log.append(
                &Event::new("ssh", "login_attempt", &peer, session)
                    .with("user", &user)
                    .with("password", &password)
                    .with("result", "denied"),
            );
            if write!(writer, "Permission denied, please try again.\r\n").is_err() {
                return;
            }
            continue;
        }

        let _ = log.append(
            &Event::new("ssh", "login_attempt", &peer, session)
                .with("user", &user)
                .with("password", &password)
                .with("result", "accepted"),
        );
        let _ =
            log.append(&Event::new("ssh", "login_accepted", &peer, session).with("user", &user));
        break;
    }

    if write!(writer, "Welcome to Ubuntu 22.04.3 LTS\r\n").is_err() {
        return;
    }

    loop {
        if Instant::now() >= plazo {
            let _ = log.append(&Event::new("ssh", "sesion_timeout", &peer, session));
            break;
        }
        if write!(writer, "{SHELL_PROMPT}").is_err() {
            return;
        }
        let command = match read_line(&mut reader, plazo) {
            Lectura::Linea(command) => command,
            Lectura::Fin => break,
            Lectura::DemasiadoLarga => {
                let _ = log.append(&Event::new("ssh", "linea_demasiada_larga", &peer, session));
                break;
            }
            Lectura::TiempoAgotado => {
                let _ = log.append(&Event::new("ssh", "sesion_timeout", &peer, session));
                break;
            }
        };

        let response = shell::respond(&command);
        let _ = log.append(&Event::new("ssh", "command", &peer, session).with("command", &command));
        if let Some(descarga) = &response.download {
            let _ = log.append(
                &Event::new("ssh", "download_attempt", &peer, session)
                    .with("command", &command)
                    .with("url", &descarga.url)
                    .with("archivo", &descarga.archivo)
                    .with("bytes", &descarga.bytes.to_string())
                    .with("herramienta", descarga.herramienta),
            );
        }
        if !response.output.is_empty() && write!(writer, "{}\r\n", response.output).is_err() {
            return;
        }
        if response.exit {
            break;
        }
    }

    let duration = started.elapsed().as_secs();
    let _ = log.append(
        &Event::new("ssh", "session_end", &peer, session).with("duration", &format!("{duration}s")),
    );
}

/// Starts the fake web login on `bind` and returns the address actually bound.
pub fn start_http_trap(bind: SocketAddr, log: Arc<EventLog>) -> std::io::Result<SocketAddr> {
    // Same guard as the SSH trap: the library never binds outside the loopback.
    if !is_loopback(&bind.ip()) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            LOOPBACK_ONLY,
        ));
    }
    let listener = TcpListener::bind(bind)?;
    let local = listener.local_addr()?;
    let sessions = Arc::new(AtomicU64::new(0));

    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let stream = match stream {
                Ok(stream) => stream,
                Err(_) => break,
            };
            let log = Arc::clone(&log);
            let sessions = Arc::clone(&sessions);
            std::thread::spawn(move || {
                let id = sessions.fetch_add(1, Ordering::Relaxed) + 1;
                serve_http_session(stream, &log, &format!("h-{id}"));
            });
        }
    });

    Ok(local)
}

/// Serves one HTTP request: the fake login page, the fake login and a logged 404.
pub fn serve_http_session(stream: TcpStream, log: &EventLog, session: &str) {
    serve_http_session_con_tiempo(stream, log, session, TIEMPO_MAXIMO_SESION);
}

/// Igual que [`serve_http_session`], pero con el tiempo máximo como parámetro.
pub fn serve_http_session_con_tiempo(
    stream: TcpStream,
    log: &EventLog,
    session: &str,
    tiempo_maximo: Duration,
) {
    let peer = peer_address(&stream);
    let mut writer = match stream.try_clone() {
        Ok(writer) => writer,
        Err(_) => return,
    };
    let mut reader = stream;
    // Una petición web tampoco puede quedar esperando para siempre.
    let _ = reader.set_read_timeout(Some(tiempo_maximo));
    // Y lo mismo al escribir: un cliente que no lee no puede dejar el hilo colgado.
    let _ = reader.set_write_timeout(Some(tiempo_maximo));
    let plazo = Instant::now() + tiempo_maximo;

    let head = match read_head(&mut reader) {
        Some(head) => head,
        None => return,
    };
    if Instant::now() >= plazo {
        return;
    }
    let mut lines = head.split("\r\n");
    let request_line = lines.next().unwrap_or("");
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let path = parts.next().unwrap_or("/").to_string();
    // La query string no es parte de la ruta: «/?foo=bar» es la página de login.
    // En el registro se guarda la ruta completa, con la query.
    let ruta = path.split('?').next().unwrap_or("/").to_string();

    let mut content_length = 0usize;
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            if name.trim().eq_ignore_ascii_case("content-length") {
                content_length = value.trim().parse().unwrap_or(0);
            }
        }
    }

    let mut body = String::new();
    if method.eq_ignore_ascii_case("POST") && content_length > 0 {
        let size = content_length.min(MAX_BODY_BYTES);
        let mut buffer = vec![0u8; size];
        if reader.read_exact(&mut buffer).is_ok() {
            body = String::from_utf8_lossy(&buffer).to_string();
        }
    }

    let (status, page) = match (method.as_str(), ruta.as_str()) {
        ("GET", "/") => {
            let _ = log.append(
                &Event::new("http", "http_get", &peer, session)
                    .with("method", "GET")
                    .with("path", &path)
                    .with("status", "200"),
            );
            ("200 OK", LOGIN_PAGE.to_string())
        }
        ("POST", "/login") => {
            let form = parse_form(&body);
            let user = form
                .iter()
                .find(|(k, _)| k == "user")
                .map(|(_, v)| v.clone())
                .unwrap_or_default();
            let password = form
                .iter()
                .find(|(k, _)| k == "password")
                .map(|(_, v)| v.clone())
                .unwrap_or_default();
            let _ = log.append(
                &Event::new("http", "http_post", &peer, session)
                    .with("method", "POST")
                    .with("path", &path)
                    .with("user", &user)
                    .with("password", &password)
                    .with("status", "200"),
            );
            ("200 OK", PANEL_PAGE.to_string())
        }
        // Las páginas del «banco» de mentira: cada clic queda anotado, para saber qué
        // busca el atacante una vez que cree que entró.
        ("GET", "/panel")
        | ("GET", "/cuenta")
        | ("GET", "/transferencia")
        | ("GET", "/descargar-factura") => {
            let _ = log.append(
                &Event::new("http", "http_click", &peer, session)
                    .with("method", "GET")
                    .with("path", &path)
                    .with("status", "200"),
            );
            ("200 OK", PAGINA_FALSA.to_string())
        }
        _ => {
            let _ = log.append(
                &Event::new("http", "http_get", &peer, session)
                    .with("method", &method)
                    .with("path", &path)
                    .with("status", "404"),
            );
            ("404 Not Found", NOT_FOUND_PAGE.to_string())
        }
    };

    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{page}",
        page.len()
    );
    let _ = writer.write_all(response.as_bytes());
    let _ = writer.flush();
}

/// Fake login page of the web trap.
pub const LOGIN_PAGE: &str = "<!doctype html>\n<html lang=\"es\">\n<head><meta charset=\"utf-8\"><title>Banco Popular — Acceso seguro</title></head>\n<body>\n<h1>Banco Popular</h1>\n<p>Introduzca sus credenciales para continuar.</p>\n<form method=\"post\" action=\"/login\">\n<p><label>Usuario <input name=\"user\" type=\"text\"></label></p>\n<p><label>Contraseña <input name=\"password\" type=\"password\"></label></p>\n<p><button type=\"submit\">Ingresar</button></p>\n</form>\n</body>\n</html>\n";

/// Answer of the web trap after a login. It never authenticates anything.
///
/// It shows a fake banking panel with links: every click on them is recorded, so the
/// operator can see what the attacker looks for once it believes it got in.
pub const PANEL_PAGE: &str = "<!doctype html>\n<html lang=\"es\">\n<head><meta charset=\"utf-8\"><title>Banco Popular — Mi cuenta</title></head>\n<body>\n<h1>Banco Popular</h1>\n<p>Sesión iniciada. El acceso se ha registrado.</p>\n<ul>\n<li><a href=\"/cuenta\">Mi cuenta</a></li>\n<li><a href=\"/transferencia\">Transferencia</a></li>\n<li><a href=\"/descargar-factura\">Descargar factura</a></li>\n</ul>\n</body>\n</html>\n";

/// Any page of the fake bank. It shows plausible but empty content.
pub const PAGINA_FALSA: &str = "<!doctype html>\n<html lang=\"es\">\n<head><meta charset=\"utf-8\"><title>Banco Popular</title></head>\n<body>\n<h1>Banco Popular</h1>\n<p>Documento sin contenido. La navegación quedó registrada.</p>\n</body>\n</html>\n";

/// Answer for any other path.
pub const NOT_FOUND_PAGE: &str = "<!doctype html>\n<html lang=\"es\">\n<head><meta charset=\"utf-8\"><title>404</title></head>\n<body>\n<h1>404 — página no encontrada</h1>\n</body>\n</html>\n";

/// Parses an `application/x-www-form-urlencoded` body.
pub fn parse_form(body: &str) -> Vec<(String, String)> {
    body.split('&')
        .filter(|pair| !pair.is_empty())
        .map(|pair| match pair.split_once('=') {
            Some((key, value)) => (url_decode(key), url_decode(value)),
            None => (url_decode(pair), String::new()),
        })
        .collect()
}

/// Decodes the percent encoding of a form value.
pub fn url_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut index = 0usize;
    while index < bytes.len() {
        match bytes[index] {
            b'+' => {
                out.push(b' ');
                index += 1;
            }
            b'%' if index + 2 < bytes.len() => {
                let hex = match std::str::from_utf8(&bytes[index + 1..index + 3]) {
                    Ok(hex) => hex,
                    Err(_) => {
                        out.push(bytes[index]);
                        index += 1;
                        continue;
                    }
                };
                match u8::from_str_radix(hex, 16) {
                    Ok(byte) => {
                        out.push(byte);
                        index += 3;
                    }
                    Err(_) => {
                        out.push(bytes[index]);
                        index += 1;
                    }
                }
            }
            other => {
                out.push(other);
                index += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).to_string()
}

fn peer_address(stream: &TcpStream) -> String {
    stream
        .peer_addr()
        .map(|address| address.to_string())
        .unwrap_or_else(|_| "desconocido".to_string())
}

/// What a read from the client returned.
enum Lectura {
    /// A complete line arrived.
    Linea(String),
    /// The client closed the connection.
    Fin,
    /// The client stayed silent for too long.
    TiempoAgotado,
    /// The line was longer than the accepted maximum.
    DemasiadoLarga,
}

/// Lee una línea del cliente, con dos límites:
///
/// - **Tope de longitud**: nunca se guardan más de [`MAX_LINE_BYTES`] bytes, así que un
///   cliente que no manda el salto de línea no puede hacer crecer la memoria.
/// - **Plazo absoluto**: se comprueba en cada byte, de modo que un atacante que gotea
///   datos (uno cada 100 ms) tampoco puede alargar la sesión indefinidamente.
fn read_line(reader: &mut BufReader<TcpStream>, plazo: Instant) -> Lectura {
    let mut linea: Vec<u8> = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        if Instant::now() >= plazo {
            return Lectura::TiempoAgotado;
        }
        match reader.read(&mut byte) {
            Ok(0) => {
                return if linea.is_empty() {
                    Lectura::Fin
                } else {
                    Lectura::Linea(cadena_de(&linea))
                };
            }
            Ok(_) => {
                if byte[0] == b'\n' {
                    return Lectura::Linea(cadena_de(&linea));
                }
                linea.push(byte[0]);
                if linea.len() > MAX_LINE_BYTES {
                    return Lectura::DemasiadoLarga;
                }
            }
            Err(error) if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                // O se agotó el plazo, o el cliente se quedó callado: en los dos casos
                // la sesión se cierra y queda anotada.
                return Lectura::TiempoAgotado;
            }
            Err(_) => return Lectura::Fin,
        }
    }
}

/// Convierte los bytes de una línea en texto, sin el salto de línea final.
fn cadena_de(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes)
        .trim_end_matches(['\r', '\n'])
        .to_string()
}

/// Reads the request head (up to the empty line) one byte at a time.
fn read_head(reader: &mut TcpStream) -> Option<String> {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        match reader.read(&mut byte) {
            Ok(0) | Err(_) => return None,
            Ok(_) => {
                head.push(byte[0]);
                if head.len() >= MAX_HEAD_BYTES {
                    return None;
                }
                if head.ends_with(b"\r\n\r\n") {
                    return Some(String::from_utf8_lossy(&head).to_string());
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_guard_accepts_local_addresses() {
        assert!(is_loopback(&"127.0.0.1".parse().unwrap()));
        assert!(is_loopback(&"::1".parse().unwrap()));
        assert!(!is_loopback(&"192.168.1.10".parse().unwrap()));
        assert!(!is_loopback(&"0.0.0.0".parse().unwrap()));
    }

    #[test]
    fn las_trampas_no_escuchan_fuera_del_loopback() {
        // La guarda vive dentro de las funciones que abren el socket: usar la
        // biblioteca no permite saltársela.
        let ruta = std::env::temp_dir().join("honeypot-guarda-test.jsonl");
        let log = std::sync::Arc::new(
            crate::log::EventLog::open(&ruta).expect("no se pudo abrir el registro"),
        );

        let error = start_ssh_trap("0.0.0.0:0".parse().unwrap(), std::sync::Arc::clone(&log))
            .expect_err("la trampa SSH no debe escuchar fuera del loopback");
        assert!(
            error.to_string().contains("loopback"),
            "el error debe explicar la guarda: {error}"
        );

        let error = start_http_trap("0.0.0.0:0".parse().unwrap(), std::sync::Arc::clone(&log))
            .expect_err("la trampa web no debe escuchar fuera del loopback");
        assert!(
            error.to_string().contains("loopback"),
            "el error debe explicar la guarda: {error}"
        );
    }

    #[test]
    fn parses_a_form_body() {
        let form = parse_form("user=admin&password=secreto%20con%20espacios");
        assert_eq!(form[0], ("user".to_string(), "admin".to_string()));
        assert_eq!(
            form[1],
            ("password".to_string(), "secreto con espacios".to_string())
        );
    }

    #[test]
    fn decodes_plus_and_percent() {
        assert_eq!(url_decode("a+b"), "a b");
        assert_eq!(url_decode("%2F"), "/");
        assert_eq!(url_decode("100%"), "100%");
    }

    #[test]
    fn login_page_contains_a_form() {
        assert!(LOGIN_PAGE.contains("<form"));
        assert!(LOGIN_PAGE.contains("name=\"user\""));
        assert!(LOGIN_PAGE.contains("name=\"password\""));
    }
}
