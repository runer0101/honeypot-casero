//! Command line interface of the honeypot.

use honeypot::attack::{self, DEFAULT_PASSWORDS};
use honeypot::log::EventLog;
use honeypot::{trap, viewer};
use std::env;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

const USAGE: &str = "\
honeypot — trampa casera para laboratorios autorizados

Uso:
  honeypot serve  [--bind 127.0.0.1] [--ssh-port 2222] [--http-port 8080] [--log RUTA]
  honeypot show   [--log RUTA] [--json]
  honeypot attack [--target 127.0.0.1:2222] [--passwords N]
  honeypot --help

Notas:
  · El honeypot solo acepta direcciones de loopback (127.0.0.1 o ::1).
  · La trampa SSH es una emulación de banner y prompt en texto, no un servidor SSH real.
  · La trampa web nunca autentica a nadie: solo registra lo que se le envía.
";

const LEGAL_NOTE: &str = "el honeypot solo acepta direcciones de loopback (127.0.0.1 o ::1); \
este laboratorio es una actividad autorizada";

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    match run(&args) {
        Ok(code) => code,
        Err(error) => {
            eprintln!("honeypot: {error}");
            ExitCode::from(2)
        }
    }
}

fn run(args: &[String]) -> Result<ExitCode, String> {
    match args.first().map(String::as_str) {
        Some("serve") => serve(&args[1..]),
        Some("show") => show(&args[1..]),
        Some("attack") => run_attack(&args[1..]),
        Some("-h") | Some("--help") | None => {
            print!("{USAGE}");
            Ok(ExitCode::SUCCESS)
        }
        Some(other) => Err(format!("subcomando desconocido: {other}")),
    }
}

fn serve(args: &[String]) -> Result<ExitCode, String> {
    let mut bind = "127.0.0.1".to_string();
    let mut ssh_port: u16 = 2222;
    let mut http_port: u16 = 8080;
    let mut log_path = PathBuf::from("logs/honeypot.jsonl");

    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--bind" => {
                bind = iter
                    .next()
                    .ok_or_else(|| "falta la dirección en --bind".to_string())?
                    .clone()
            }
            "--ssh-port" => {
                ssh_port = iter
                    .next()
                    .ok_or_else(|| "falta el puerto en --ssh-port".to_string())?
                    .parse()
                    .map_err(|_| "el puerto SSH debe ser un número".to_string())?
            }
            "--http-port" => {
                http_port = iter
                    .next()
                    .ok_or_else(|| "falta el puerto en --http-port".to_string())?
                    .parse()
                    .map_err(|_| "el puerto HTTP debe ser un número".to_string())?
            }
            "--log" => {
                log_path = PathBuf::from(
                    iter.next()
                        .ok_or_else(|| "falta la ruta en --log".to_string())?,
                )
            }
            other => return Err(format!("opción desconocida: {other}")),
        }
    }

    let address: IpAddr = bind
        .parse()
        .map_err(|_| format!("dirección inválida: {bind}"))?;
    if !trap::is_loopback(&address) {
        return Err(LEGAL_NOTE.to_string());
    }

    let log = EventLog::open(&log_path)
        .map_err(|e| format!("no se pudo abrir el registro {}: {e}", log_path.display()))?;
    log.set_echo(true);
    let log = Arc::new(log);

    let ssh = trap::start_ssh_trap(SocketAddr::new(address, ssh_port), Arc::clone(&log))
        .map_err(|e| format!("no se pudo abrir la trampa SSH en {bind}:{ssh_port}: {e}"))?;
    let http = trap::start_http_trap(SocketAddr::new(address, http_port), Arc::clone(&log))
        .map_err(|e| format!("no se pudo abrir la trampa web en {bind}:{http_port}: {e}"))?;

    println!("⚠  Honeypot de laboratorio — actividad autorizada");
    println!("   Trampa SSH (emulación en texto): {ssh}");
    println!("   Trampa web (login falso):         {http}");
    println!("   Registro: {}", log_path.display());
    println!("   Ctrl-C para detener.");
    println!();

    loop {
        std::thread::sleep(Duration::from_secs(3600));
    }
}

fn show(args: &[String]) -> Result<ExitCode, String> {
    let mut log_path = PathBuf::from("logs/honeypot.jsonl");
    let mut json = false;

    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--log" => {
                log_path = PathBuf::from(
                    iter.next()
                        .ok_or_else(|| "falta la ruta en --log".to_string())?,
                )
            }
            "--json" => json = true,
            other => return Err(format!("opción desconocida: {other}")),
        }
    }

    let sessions = viewer::read_sessions(&log_path)?;
    if json {
        println!("{}", viewer::to_json(&sessions));
    } else {
        print!("{}", viewer::render(&sessions));
    }
    Ok(ExitCode::SUCCESS)
}

fn run_attack(args: &[String]) -> Result<ExitCode, String> {
    let mut target = "127.0.0.1:2222".to_string();
    let mut attempts = 3usize;

    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--target" => {
                target = iter
                    .next()
                    .ok_or_else(|| "falta el destino en --target".to_string())?
                    .clone()
            }
            "--passwords" => {
                attempts = iter
                    .next()
                    .ok_or_else(|| "falta la cantidad en --passwords".to_string())?
                    .parse()
                    .map_err(|_| "la cantidad de contraseñas debe ser un número".to_string())?
            }
            other => return Err(format!("opción desconocida: {other}")),
        }
    }

    let host = target
        .rsplit_once(':')
        .map(|(host, _)| host)
        .unwrap_or(&target);
    let address: IpAddr = host
        .parse()
        .map_err(|_| format!("destino inválido: {target}"))?;
    if !trap::is_loopback(&address) {
        return Err(
            "el cliente de ataque solo se conecta a direcciones de loopback (127.0.0.1 o ::1); \
             este material es para un laboratorio autorizado"
                .to_string(),
        );
    }

    let passwords: Vec<&str> = DEFAULT_PASSWORDS.iter().take(attempts).copied().collect();
    let outcome = attack::run(&target, &passwords, Duration::from_secs(5))?;

    println!("Banner del honeypot: {}", outcome.banner);
    for (index, attempt) in outcome.attempts.iter().enumerate() {
        println!(
            "Intento {} · {}/{} → {}",
            index + 1,
            attempt.user,
            attempt.password,
            attempt.response
        );
    }
    if outcome.commands.is_empty() {
        println!("El atacante no llegó a obtener una sesión.");
        return Ok(ExitCode::SUCCESS);
    }

    println!("Sesión obtenida. Órdenes ejecutadas:");
    for (command, response) in &outcome.commands {
        println!("$ {command}");
        for line in response.lines() {
            println!("  {line}");
        }
    }
    Ok(ExitCode::SUCCESS)
}
