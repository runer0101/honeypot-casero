//! Event model, JSONL log writer and time helpers.
//!
//! The log is one JSON object per line. Every value is a string, which keeps the file
//! readable in a text editor and lets the viewer parse it without a JSON crate.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

/// One recorded event.
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

    /// Adds one extra field to the event.
    pub fn with(mut self, key: &str, value: &str) -> Event {
        self.fields.push((key.to_string(), value.to_string()));
        self
    }

    /// Serializes the event as a single JSON object.
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

/// Escapes a string into a JSON literal.
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

/// Appends events to a JSONL file.
pub struct EventLog {
    path: PathBuf,
    file: Mutex<File>,
    echo: AtomicBool,
}

impl EventLog {
    /// Opens (or creates) the log file and its parent directory.
    pub fn open(path: &Path) -> io::Result<EventLog> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)?;
            }
        }
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        Ok(EventLog {
            path: path.to_path_buf(),
            file: Mutex::new(file),
            echo: AtomicBool::new(false),
        })
    }

    /// When enabled, every event is also printed in a readable line.
    pub fn set_echo(&self, echo: bool) {
        self.echo.store(echo, Ordering::Relaxed);
    }

    /// Writes one event and flushes it, so the file is always readable while the trap runs.
    pub fn append(&self, event: &Event) -> io::Result<()> {
        {
            let mut guard = self
                .file
                .lock()
                .map_err(|_| io::Error::other("el mutex del registro quedó envenenado"))?;
            writeln!(guard, "{}", event.to_json())?;
            guard.flush()?;
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
}

/// Current time as an ISO-8601 UTC timestamp (`2026-11-20T19:37:00Z`).
pub fn now_iso8601() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format_epoch(secs)
}

/// Formats a Unix timestamp as ISO-8601 UTC.
pub fn format_epoch(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let rest = secs % 86_400;
    let (hour, minute, second) = (rest / 3600, (rest % 3600) / 60, rest % 60);
    let (year, month, day) = civil_from_days(days);
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

/// Converts days since the Unix epoch into a civil date (Howard Hinnant's algorithm).
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

/// Parses a flat JSON object whose values are strings (or bare numbers).
///
/// Returns `None` when the line is not a JSON object.
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
}
