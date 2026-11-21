//! Las trampas: un servicio de acceso tipo SSH en texto plano y un acceso web falso.

use crate::log::{Event, EventLog};
use crate::shell;
use std::io::{BufReader, ErrorKind, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Banner que anuncia la trampa tipo SSH.
pub const SSH_BANNER: &str = "SSH-2.0-OpenSSH_9.6 Ubuntu-3ubuntu13";

/// Prompt del shell falso.
pub const SHELL_PROMPT: &str = "root@victima:~# ";

/// Cuántas credenciales se rechazan antes de dejar entrar al atacante.
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

/// Tamaño máximo admitido para la cabecera de una petición HTTP.
const MAX_HEAD_BYTES: usize = 8_192;

/// Tamaño máximo admitido para el cuerpo de una petición HTTP.
const MAX_BODY_BYTES: usize = 4_096;

/// Tamaño máximo admitido para una línea del shell falso.
///
/// Un cliente que nunca manda el salto de línea no puede hacer crecer la cadena sin límite.
const MAX_LINE_BYTES: usize = 8_192;

/// Mensaje que se usa cuando alguien intenta escuchar fuera del loopback.
const LOOPBACK_ONLY: &str = "el honeypot solo acepta direcciones de loopback (127.0.0.1 o ::1); \
este laboratorio es una actividad autorizada";

/// `true` para las direcciones de loopback en las que la trampa puede escuchar.
pub fn is_loopback(address: &IpAddr) -> bool {
    address.is_loopback()
}

/// Levanta la trampa tipo SSH en `bind` y devuelve la dirección realmente escuchada.
pub fn start_ssh_trap(bind: SocketAddr, log: Arc<EventLog>) -> std::io::Result<SocketAddr> {
    // La guarda vive aquí, no solo en la CLI: quien use la biblioteca también queda
    // protegido de escuchar fuera del loopback.
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

/// Atiende una sesión tipo SSH: banner, credenciales y después el shell falso.
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

    let duration = started.elapsed().as_millis();
    let _ = log.append(
        &Event::new("ssh", "session_end", &peer, session)
            .with("duration", &format!("{duration}ms")),
    );
}

/// Levanta el acceso web falso en `bind` y devuelve la dirección realmente escuchada.
pub fn start_http_trap(bind: SocketAddr, log: Arc<EventLog>) -> std::io::Result<SocketAddr> {
    // La misma guarda que la trampa SSH: la biblioteca nunca escucha fuera del loopback.
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

/// Atiende una petición HTTP: la página de login falsa, el login falso y un 404 anotado.
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
    let mut chunked = false;
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            let name = name.trim();
            if name.eq_ignore_ascii_case("content-length") {
                content_length = value.trim().parse().unwrap_or(0);
            } else if name.eq_ignore_ascii_case("transfer-encoding")
                && value.to_ascii_lowercase().contains("chunked")
            {
                // El cuerpo llega por trozos: se ensambla al leerlo.
                chunked = true;
            }
        }
    }

    // El cuerpo se lee solo en el POST: es la única petición con formulario. Un GET
    // con `Content-Length` se responde sin leer nada, como hasta ahora.
    let es_post = method.eq_ignore_ascii_case("POST");
    let cuerpo = if !chunked && content_length > MAX_BODY_BYTES {
        // Un cuerpo declarado enorme se rechaza sin leerlo: truncarlo perdería
        // credenciales sin dejar rastro.
        LecturaCuerpo::DemasiadoGrande {
            tamano: content_length,
            declarado: Some(content_length),
        }
    } else if es_post {
        leer_cuerpo(&mut reader, content_length, chunked)
    } else {
        LecturaCuerpo::Completo(Vec::new())
    };

    let bytes = match cuerpo {
        LecturaCuerpo::Completo(bytes) => bytes,
        LecturaCuerpo::DemasiadoGrande { tamano, declarado } => {
            let mut evento = Event::new("http", "http_cuerpo_demasiado_grande", &peer, session)
                .with("method", &method)
                .with("path", &path)
                .with("tamano", &tamano.to_string())
                .with("status", "413")
                .with(
                    "motivo",
                    &format!(
                        "el cuerpo enviado supera el máximo admitido ({MAX_BODY_BYTES} bytes)"
                    ),
                );
            if let Some(declarado) = declarado {
                evento = evento.with("content_length", &declarado.to_string());
            }
            let _ = log.append(&evento);
            responder(
                &mut writer,
                "413 Payload Too Large",
                PAGINA_CUERPO_DEMASIADO_GRANDE,
            );
            // Se descarta lo que el cliente ya enviara: si no, al cerrar la conexión
            // con datos sin leer, el cliente puede perder la respuesta.
            let pendiente = declarado.unwrap_or(MAX_BODY_BYTES).min(1024 * 1024);
            descartar_resto(&mut reader, pendiente);
            return;
        }
        LecturaCuerpo::Invalido { motivo } => {
            let _ = log.append(
                &Event::new("http", "http_cuerpo_invalido", &peer, session)
                    .with("method", &method)
                    .with("path", &path)
                    .with("motivo", &motivo),
            );
            // La sesión se cierra aquí: un cuerpo mal formado no se puede interpretar.
            return;
        }
    };

    // Si el cuerpo no es UTF-8 válido, el texto puede no coincidir con lo enviado:
    // se guarda además el hexadecimal exacto, para la evidencia forense.
    let (cuerpo_texto, cuerpo_hex) = match std::str::from_utf8(&bytes) {
        Ok(texto) => (texto.to_string(), None),
        Err(_) => (
            String::from_utf8_lossy(&bytes).to_string(),
            Some(a_hex(&bytes)),
        ),
    };

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
            let form = parse_form(&cuerpo_texto);
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
            let mut evento = Event::new("http", "http_post", &peer, session)
                .with("method", "POST")
                .with("path", &path)
                .with("user", &user)
                .with("password", &password)
                .with("status", "200");
            if let Some(hex) = &cuerpo_hex {
                // El cuerpo no es UTF-8 válido: el hexadecimal conserva los bytes
                // exactos que envió el atacante.
                evento = evento.with("cuerpo_hex", hex);
            }
            let _ = log.append(&evento);
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

    responder(&mut writer, status, &page);
}

/// Escribe una respuesta HTTP con su página y cierra la conexión.
fn responder(writer: &mut TcpStream, status: &str, page: &str) {
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{page}",
        page.len()
    );
    let _ = writer.write_all(response.as_bytes());
    let _ = writer.flush();
}

/// Lee y tira lo que el cliente ya envió, para poder cerrar la conexión sin reset.
///
/// Sin esto, cerrar con datos sin leer provoca un RST y el cliente puede perder la
/// respuesta que acabamos de enviar.
fn descartar_resto(reader: &mut TcpStream, maximo: usize) {
    let _ = reader.set_read_timeout(Some(Duration::from_millis(100)));
    let mut buffer = [0u8; 4096];
    let mut leidos = 0usize;
    while leidos < maximo {
        match reader.read(&mut buffer) {
            Ok(0) => break,
            Ok(cantidad) => leidos += cantidad,
            Err(_) => break,
        }
    }
}

/// Convierte bytes en hexadecimal en minúsculas, sin espacios.
fn a_hex(bytes: &[u8]) -> String {
    const DIGITOS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(DIGITOS[(byte >> 4) as usize] as char);
        out.push(DIGITOS[(byte & 0x0f) as usize] as char);
    }
    out
}

/// Página de login falsa de la trampa web.
pub const LOGIN_PAGE: &str = "<!doctype html>\n<html lang=\"es\">\n<head><meta charset=\"utf-8\"><title>Banco Popular — Acceso seguro</title></head>\n<body>\n<h1>Banco Popular</h1>\n<p>Introduzca sus credenciales para continuar.</p>\n<form method=\"post\" action=\"/login\">\n<p><label>Usuario <input name=\"user\" type=\"text\"></label></p>\n<p><label>Contraseña <input name=\"password\" type=\"password\"></label></p>\n<p><button type=\"submit\">Ingresar</button></p>\n</form>\n</body>\n</html>\n";

/// Respuesta de la trampa web después de un login. No autentica a nadie.
///
/// Muestra un panel bancario falso con enlaces: cada clic queda anotado, para que el
/// operador vea qué busca el atacante cuando cree que entró.
pub const PANEL_PAGE: &str = "<!doctype html>\n<html lang=\"es\">\n<head><meta charset=\"utf-8\"><title>Banco Popular — Mi cuenta</title></head>\n<body>\n<h1>Banco Popular</h1>\n<p>Sesión iniciada. El acceso se ha registrado.</p>\n<ul>\n<li><a href=\"/cuenta\">Mi cuenta</a></li>\n<li><a href=\"/transferencia\">Transferencia</a></li>\n<li><a href=\"/descargar-factura\">Descargar factura</a></li>\n</ul>\n</body>\n</html>\n";

/// Cualquier página del banco falso: contenido verosímil pero vacío.
pub const PAGINA_FALSA: &str = "<!doctype html>\n<html lang=\"es\">\n<head><meta charset=\"utf-8\"><title>Banco Popular</title></head>\n<body>\n<h1>Banco Popular</h1>\n<p>Documento sin contenido. La navegación quedó registrada.</p>\n</body>\n</html>\n";

/// Respuesta para cualquier otra ruta.
pub const NOT_FOUND_PAGE: &str = "<!doctype html>\n<html lang=\"es\">\n<head><meta charset=\"utf-8\"><title>404</title></head>\n<body>\n<h1>404 — página no encontrada</h1>\n</body>\n</html>\n";

/// Respuesta para un cuerpo que supera el máximo admitido.
///
/// El intento queda anotado: no se trunca el cuerpo en silencio, se rechaza.
pub const PAGINA_CUERPO_DEMASIADO_GRANDE: &str = "<!doctype html>\n<html lang=\"es\">\n<head><meta charset=\"utf-8\"><title>413 — petición demasiado grande</title></head>\n<body>\n<h1>413 — el contenido enviado es demasiado grande</h1>\n<p>La petición se ha rechazado y el intento ha quedado registrado.</p>\n</body>\n</html>\n";

/// Lo que devolvió la lectura del cuerpo de una petición HTTP.
enum LecturaCuerpo {
    /// El cuerpo llegó entero.
    Completo(Vec<u8>),
    /// El cuerpo es más grande de lo admitido.
    DemasiadoGrande {
        /// Tamaño total (declarado o acumulado).
        tamano: usize,
        /// Tamaño declarado en `Content-Length`, si lo había.
        declarado: Option<usize>,
    },
    /// El cuerpo está mal formado y no se puede interpretar.
    Invalido {
        /// Explicación del fallo, en texto claro.
        motivo: String,
    },
}

/// Lee el cuerpo de una petición HTTP.
///
/// Con `Content-Length` se leen exactamente los bytes declarados. Con
/// `Transfer-Encoding: chunked` se ensamblan los trozos: tamaño en hexadecimal,
/// datos y CRLF, hasta el trozo de tamaño 0.
fn leer_cuerpo(reader: &mut TcpStream, content_length: usize, chunked: bool) -> LecturaCuerpo {
    if chunked {
        return leer_cuerpo_por_trozos(reader);
    }
    if content_length > MAX_BODY_BYTES {
        return LecturaCuerpo::DemasiadoGrande {
            tamano: content_length,
            declarado: Some(content_length),
        };
    }
    let mut buffer = vec![0u8; content_length];
    if reader.read_exact(&mut buffer).is_err() {
        // El cuerpo declarado no llegó entero: se sigue como hasta ahora, con un
        // cuerpo vacío.
        return LecturaCuerpo::Completo(Vec::new());
    }
    LecturaCuerpo::Completo(buffer)
}

/// Ensambla un cuerpo enviado por trozos (`Transfer-Encoding: chunked`).
fn leer_cuerpo_por_trozos(reader: &mut TcpStream) -> LecturaCuerpo {
    let mut cuerpo: Vec<u8> = Vec::new();
    loop {
        let linea = match leer_linea_http(reader) {
            Ok(linea) => linea,
            Err(motivo) => return LecturaCuerpo::Invalido { motivo },
        };
        // El tamaño va en hexadecimal y puede llevar extensiones tras un «;».
        let texto = linea.split(';').next().unwrap_or("").trim();
        if texto.is_empty() {
            return LecturaCuerpo::Invalido {
                motivo: "el tamaño del trozo viene vacío".to_string(),
            };
        }
        let tamano = match u64::from_str_radix(texto, 16) {
            Ok(tamano) => tamano,
            Err(_) => {
                return LecturaCuerpo::Invalido {
                    motivo: format!("el tamaño del trozo no es hexadecimal: \"{texto}\""),
                }
            }
        };
        if tamano == 0 {
            // Fin del cuerpo: se leen las cabeceras de cola hasta la línea vacía.
            loop {
                match leer_linea_http(reader) {
                    Ok(linea) => {
                        if linea.is_empty() {
                            break;
                        }
                    }
                    Err(motivo) => return LecturaCuerpo::Invalido { motivo },
                }
            }
            return LecturaCuerpo::Completo(cuerpo);
        }

        let limite = usize::try_from(tamano).unwrap_or(usize::MAX);
        if cuerpo.len().saturating_add(limite) > MAX_BODY_BYTES {
            return LecturaCuerpo::DemasiadoGrande {
                tamano: cuerpo.len().saturating_add(limite),
                declarado: None,
            };
        }

        let mut trozo = vec![0u8; limite];
        if reader.read_exact(&mut trozo).is_err() {
            return LecturaCuerpo::Invalido {
                motivo: format!(
                    "el tamaño del trozo no cuadra: se esperaban {limite} bytes y llegaron menos"
                ),
            };
        }
        let mut fin = [0u8; 2];
        if reader.read_exact(&mut fin).is_err() || &fin != b"\r\n" {
            return LecturaCuerpo::Invalido {
                motivo: "el trozo no termina en CRLF".to_string(),
            };
        }
        cuerpo.extend_from_slice(&trozo);
    }
}

/// Lee una línea de la conexión HTTP (hasta el salto de línea), con un tope de longitud.
fn leer_linea_http(reader: &mut TcpStream) -> Result<String, String> {
    let mut linea: Vec<u8> = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        match reader.read(&mut byte) {
            Ok(0) => {
                return Err("la conexión se cerró antes de terminar la línea".to_string());
            }
            Ok(_) => {
                if byte[0] == b'\n' {
                    if linea.last() == Some(&b'\r') {
                        linea.pop();
                    }
                    return Ok(String::from_utf8_lossy(&linea).to_string());
                }
                linea.push(byte[0]);
                if linea.len() > MAX_LINE_BYTES {
                    return Err("la línea del cuerpo es demasiado larga".to_string());
                }
            }
            Err(error) => return Err(format!("fallo de lectura: {error}")),
        }
    }
}

/// Analiza un cuerpo `application/x-www-form-urlencoded`.
pub fn parse_form(body: &str) -> Vec<(String, String)> {
    body.split('&')
        .filter(|pair| !pair.is_empty())
        .map(|pair| match pair.split_once('=') {
            Some((key, value)) => (url_decode(key), url_decode(value)),
            None => (url_decode(pair), String::new()),
        })
        .collect()
}

/// Decodifica la codificación porcentual de un valor de formulario.
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

/// Lo que devolvió una lectura del cliente.
enum Lectura {
    /// Llegó una línea completa.
    Linea(String),
    /// El cliente cerró la conexión.
    Fin,
    /// El cliente se quedó callado demasiado tiempo.
    TiempoAgotado,
    /// La línea era más larga que el máximo admitido.
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

/// Lee la cabecera de la petición (hasta la línea vacía) byte a byte.
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

    #[test]
    fn el_hexadecimal_es_exacto_y_en_minusculas() {
        assert_eq!(a_hex(b"se\xf1or"), "7365f16f72");
        assert_eq!(a_hex(&[]), "");
        assert_eq!(a_hex(&[0x00, 0xff]), "00ff");
    }
}
