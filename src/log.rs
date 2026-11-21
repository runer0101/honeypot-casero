//! Modelo de eventos, escritor del registro JSONL y utilidades de tiempo.
//!
//! El registro es un objeto JSON por línea. Cada valor es una cadena: así el archivo se
//! puede leer en un editor de texto y el visor lo analiza sin ninguna biblioteca de JSON.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

/// Un evento anotado.
#[derive(Debug, Clone)]
pub struct Event {
    pub ts: String,
    pub service: &'static str,
    pub event: &'static str,
    pub peer: String,
    pub session: String,
    pub fields: Vec<(String, String)>,
}

impl Event {
    pub fn new(service: &'static str, event: &'static str, peer: &str, session: &str) -> Event {
        Event {
            ts: now_iso8601(),
            service,
            event,
            peer: peer.to_string(),
            session: session.to_string(),
            fields: Vec::new(),
        }
    }

    /// Añade un campo extra al evento.
    pub fn with(mut self, key: &str, value: &str) -> Event {
        self.fields.push((key.to_string(), value.to_string()));
        self
    }

    /// Serializa el evento como un único objeto JSON.
    pub fn to_json(&self) -> String {
        let mut parts: Vec<String> = vec![
            format!("\"ts\":{}", json_escape(&self.ts)),
            format!("\"service\":{}", json_escape(self.service)),
            format!("\"event\":{}", json_escape(self.event)),
            format!("\"peer\":{}", json_escape(&self.peer)),
            format!("\"session\":{}", json_escape(&self.session)),
        ];
        for (key, value) in &self.fields {
            parts.push(format!("{}:{}", json_escape(key), json_escape(value)));
        }
        format!("{{{}}}", parts.join(","))
    }
}

/// Escapa una cadena para que sea un literal JSON.
pub fn json_escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Añade eventos a un archivo JSONL.
pub struct EventLog {
    path: PathBuf,
    file: Mutex<File>,
    echo: AtomicBool,
    /// Cuántos eventos se han escrito: marca cuándo toca forzar el disco.
    escritos: AtomicU64,
    /// Tamaño a partir del cual el registro se rota al abrirlo.
    max_bytes: u64,
}

/// Tamaño máximo del archivo de registro.
///
/// Superado este límite, al abrir el registro el archivo se aparta como `<archivo>.1`
/// y empieza uno nuevo: así el disco no se llena sin límite en un laboratorio que
/// funciona durante semanas.
pub const MAX_LOG_BYTES: u64 = 8 * 1024 * 1024;

/// Cuántos eventos se escriben entre dos sincronizaciones con el disco.
///
/// Un corte de luz no puede llevarse un tramo largo de eventos: cada cierto número
/// de ellos se fuerza la escritura al disco. El coste por evento sigue siendo bajo.
pub const EVENTOS_ENTRE_SYNC: u64 = 100;

impl EventLog {
    /// Abre (o crea) el archivo de registro y su carpeta.
    ///
    /// Si el archivo ya supera [`MAX_LOG_BYTES`], se aparta como `<archivo>.1` y se
    /// empieza uno nuevo.
    pub fn open(path: &Path) -> io::Result<EventLog> {
        EventLog::open_con_maximo(path, MAX_LOG_BYTES)
    }

    /// Igual que [`EventLog::open`], pero con el tamaño de rotación como parámetro:
    /// así las pruebas pueden usar un límite pequeño.
    pub fn open_con_maximo(path: &Path, max_bytes: u64) -> io::Result<EventLog> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)?;
            }
        }
        rotar_si_ya_crecio(path, max_bytes)?;
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        Ok(EventLog {
            path: path.to_path_buf(),
            file: Mutex::new(file),
            echo: AtomicBool::new(false),
            escritos: AtomicU64::new(0),
            max_bytes,
        })
    }

    /// Si está activo, cada evento se imprime también en una línea legible.
    pub fn set_echo(&self, echo: bool) {
        self.echo.store(echo, Ordering::Relaxed);
    }

    /// Escribe un evento y lo vuelca a disco, para que el archivo siempre se pueda leer mientras la trampa corre.
    pub fn append(&self, event: &Event) -> io::Result<()> {
        {
            let mut guard = self
                .file
                .lock()
                .map_err(|_| io::Error::other("el mutex del registro quedó envenenado"))?;
            writeln!(guard, "{}", event.to_json())?;
            guard.flush()?;
            // Cada cierto número de eventos se fuerza también al disco: un corte de
            // luz no puede llevarse un tramo largo de eventos.
            let escritos = self.escritos.fetch_add(1, Ordering::Relaxed) + 1;
            if escritos % EVENTOS_ENTRE_SYNC == 0 {
                // Un fallo al forzar el disco no debe perder el evento ya escrito.
                let _ = guard.sync_all();
            }
        }

        if self.echo.load(Ordering::Relaxed) {
            let mut line = format!(
                "{} [{}] {} {}",
                event.ts, event.service, event.peer, event.event
            );
            for (key, value) in &event.fields {
                line.push_str(&format!(" {key}={value}"));
            }
            println!("{line}");
        }
        Ok(())
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Tamaño a partir del cual el registro se rotará al abrirlo.
    pub fn max_bytes(&self) -> u64 {
        self.max_bytes
    }
}

/// Aparta el registro ya grande como `<archivo>.1` para empezar uno nuevo.
///
/// Solo se conserva una generación anterior: la de más antes se sustituye.
fn rotar_si_ya_crecio(path: &Path, max_bytes: u64) -> io::Result<()> {
    let tamano = match fs::metadata(path) {
        Ok(metadatos) => metadatos.len(),
        // El archivo todavía no existe: no hay nada que rotar.
        Err(_) => return Ok(()),
    };
    if tamano <= max_bytes {
        return Ok(());
    }

    let respaldo = ruta_de_respaldo(path);
    // Se elimina la generación anterior: solo se guarda una.
    match fs::remove_file(&respaldo) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    fs::rename(path, &respaldo)?;
    Ok(())
}

/// Ruta del archivo de respaldo: el original con `.1` detrás.
fn ruta_de_respaldo(path: &Path) -> PathBuf {
    let mut nombre = path.as_os_str().to_os_string();
    nombre.push(".1");
    PathBuf::from(nombre)
}

/// La hora actual como marca de tiempo ISO-8601 en UTC (`2026-11-20T19:37:00Z`).
pub fn now_iso8601() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format_epoch(secs)
}

/// Formatea una marca de tiempo Unix como ISO-8601 en UTC.
pub fn format_epoch(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let rest = secs % 86_400;
    let (hour, minute, second) = (rest / 3600, (rest % 3600) / 60, rest % 60);
    let (year, month, day) = civil_from_days(days);
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

/// Convierte los días desde la época Unix en una fecha civil (algoritmo de Howard Hinnant).
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let day_of_era = (z - era * 146_097) as u64; // [0, 146096]
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365; // [0, 399]
    let year = year_of_era as i64 + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100); // [0, 365]
    let mp = (5 * day_of_year + 2) / 153; // [0, 11]
    let day = (day_of_year - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1, 12]
    let year = if month <= 2 { year + 1 } else { year };
    (year, month, day)
}

/// Analiza un objeto JSON plano cuyos valores son cadenas (o números sin comillas).
///
/// Devuelve `None` si la línea no es un objeto JSON.
pub fn parse_flat_object(line: &str) -> Option<Vec<(String, String)>> {
    let chars: Vec<char> = line.trim().chars().collect();
    let mut index = 0usize;
    let mut fields: Vec<(String, String)> = Vec::new();

    skip_spaces(&chars, &mut index);
    if *chars.get(index)? != '{' {
        return None;
    }
    index += 1;

    loop {
        skip_spaces(&chars, &mut index);
        match chars.get(index) {
            Some('}') => {
                break;
            }
            Some('"') => {}
            _ => return None,
        }
        let key = parse_json_string(&chars, &mut index)?;
        skip_spaces(&chars, &mut index);
        if *chars.get(index)? != ':' {
            return None;
        }
        index += 1;
        skip_spaces(&chars, &mut index);

        let value = match chars.get(index) {
            Some('"') => parse_json_string(&chars, &mut index)?,
            _ => {
                let start = index;
                while let Some(c) = chars.get(index) {
                    if *c == ',' || *c == '}' {
                        break;
                    }
                    index += 1;
                }
                chars[start..index].iter().collect::<String>()
            }
        };
        fields.push((key, value));

        skip_spaces(&chars, &mut index);
        match chars.get(index) {
            Some(',') => index += 1,
            Some('}') => {
                break;
            }
            _ => return None,
        }
    }

    Some(fields)
}

fn skip_spaces(chars: &[char], index: &mut usize) {
    while let Some(c) = chars.get(*index) {
        if c.is_whitespace() {
            *index += 1;
        } else {
            break;
        }
    }
}

fn parse_json_string(chars: &[char], index: &mut usize) -> Option<String> {
    if *chars.get(*index)? != '"' {
        return None;
    }
    *index += 1;
    let mut out = String::new();
    while let Some(&c) = chars.get(*index) {
        *index += 1;
        match c {
            '"' => return Some(out),
            '\\' => {
                let escaped = *chars.get(*index)?;
                *index += 1;
                match escaped {
                    'n' => out.push('\n'),
                    'r' => out.push('\r'),
                    't' => out.push('\t'),
                    'b' => out.push('\u{8}'),
                    'f' => out.push('\u{c}'),
                    'u' => {
                        let code: String = chars.get(*index..*index + 4)?.iter().collect();
                        *index += 4;
                        let value = u32::from_str_radix(&code, 16).ok()?;
                        out.push(char::from_u32(value).unwrap_or('\u{fffd}'));
                    }
                    other => out.push(other),
                }
            }
            other => out.push(other),
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epoch_zero_is_the_unix_epoch() {
        assert_eq!(format_epoch(0), "1970-01-01T00:00:00Z");
    }

    #[test]
    fn formats_a_known_timestamp() {
        assert_eq!(format_epoch(1_700_000_000), "2023-11-14T22:13:20Z");
    }

    #[test]
    fn formats_a_leap_day() {
        assert_eq!(format_epoch(1_709_164_800), "2024-02-29T00:00:00Z");
    }

    #[test]
    fn json_escapes_quotes_and_newlines() {
        assert_eq!(json_escape("a\"b\\c\nd"), r#""a\"b\\c\nd""#);
    }

    #[test]
    fn event_json_has_the_expected_shape() {
        let event = Event::new("ssh", "login_attempt", "127.0.0.1:5000", "s-1")
            .with("user", "root")
            .with("password", "123456");
        let json = event.to_json();
        assert!(json.starts_with('{'));
        assert!(json.ends_with('}'));
        assert!(json.contains("\"service\":\"ssh\""));
        assert!(json.contains("\"event\":\"login_attempt\""));
        assert!(json.contains("\"user\":\"root\""));
    }

    #[test]
    fn parses_a_flat_object() {
        let fields =
            parse_flat_object(r#"{"ts":"2026-01-01T00:00:00Z","peer":"127.0.0.1:1","n":7}"#)
                .expect("no se pudo parsear");
        let get = |key: &str| {
            fields
                .iter()
                .find(|(k, _)| k == key)
                .map(|(_, v)| v.clone())
                .unwrap_or_default()
        };
        assert_eq!(get("ts"), "2026-01-01T00:00:00Z");
        assert_eq!(get("peer"), "127.0.0.1:1");
        assert_eq!(get("n"), "7");
    }

    #[test]
    fn parses_escaped_values() {
        let fields = parse_flat_object(r#"{"password":"a\"b"}"#).expect("no se pudo parsear");
        assert_eq!(fields[0].1, "a\"b");
    }

    #[test]
    fn rejects_a_line_that_is_not_an_object() {
        assert!(parse_flat_object("no soy json").is_none());
    }

    #[test]
    fn writes_one_object_per_line() {
        let path = std::env::temp_dir().join("honeypot-log-test.jsonl");
        let _ = std::fs::remove_file(&path);
        let log = EventLog::open(&path).expect("no se pudo abrir el log");
        log.append(&Event::new("ssh", "connect", "127.0.0.1:1", "s-1"))
            .expect("no se pudo escribir");
        log.append(&Event::new("ssh", "command", "127.0.0.1:1", "s-1").with("command", "ls"))
            .expect("no se pudo escribir");

        let content = std::fs::read_to_string(&path).expect("no se pudo leer el log");
        assert_eq!(content.lines().count(), 2);
        for line in content.lines() {
            assert!(parse_flat_object(line).is_some(), "línea inválida: {line}");
        }
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn rota_el_registro_cuando_ya_supera_el_maximo() {
        let path = std::env::temp_dir().join("honeypot-log-rotacion-test.jsonl");
        let respaldo = std::env::temp_dir().join("honeypot-log-rotacion-test.jsonl.1");
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(&respaldo);

        // Un máximo diminuto: basta un evento para superarlo.
        let log = EventLog::open_con_maximo(&path, 10).expect("no se pudo abrir el log");
        log.append(&Event::new("ssh", "connect", "127.0.0.1:1", "s-1"))
            .expect("no se pudo escribir");
        drop(log);

        // Al reabrirlo, el archivo viejo se aparta como `.1` y empieza uno nuevo.
        let log = EventLog::open_con_maximo(&path, 10).expect("no se pudo reabrir el log");
        log.append(&Event::new("ssh", "command", "127.0.0.1:1", "s-1").with("command", "ls"))
            .expect("no se pudo escribir");
        drop(log);

        assert!(
            respaldo.exists(),
            "el registro anterior debe quedar aparte como .1"
        );
        let viejo = std::fs::read_to_string(&respaldo).expect("no se pudo leer el respaldo");
        assert_eq!(viejo.lines().count(), 1);
        assert!(viejo.contains("\"event\":\"connect\""));

        let nuevo = std::fs::read_to_string(&path).expect("no se pudo leer el registro");
        assert_eq!(nuevo.lines().count(), 1);
        assert!(nuevo.contains("\"event\":\"command\""));

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(&respaldo);
    }

    #[test]
    fn solo_se_conserva_una_generacion_anterior() {
        let path = std::env::temp_dir().join("honeypot-log-rotacion-2-test.jsonl");
        let respaldo = std::env::temp_dir().join("honeypot-log-rotacion-2-test.jsonl.1");
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(&respaldo);

        for numero in 0..3 {
            let log = EventLog::open_con_maximo(&path, 10).expect("no se pudo abrir el log");
            log.append(
                &Event::new("ssh", "connect", "127.0.0.1:1", "s-1").with("n", &numero.to_string()),
            )
            .expect("no se pudo escribir");
            drop(log);
        }

        // La tercera apertura sustituyó el `.1` anterior: solo queda una generación.
        let respaldo_texto =
            std::fs::read_to_string(&respaldo).expect("no se pudo leer el respaldo");
        assert_eq!(respaldo_texto.lines().count(), 1);
        assert!(
            respaldo_texto.contains("\"n\":\"1\""),
            "contenido: {respaldo_texto}"
        );

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(&respaldo);
    }
}
