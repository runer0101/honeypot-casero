# Actividad: Honeypot casero — 5 de diciembre

Especificación de la herramienta de la segunda mitad de la actividad de ciberseguridad.
La primera mitad (el analizador de phishing) vive en el repositorio hermano
`analizador-phishing`.

## Specs

- **S1** — «Dame proyecto de ciberseguridad para poder mostrar en una actividad el 5 de
  diciembre»: la entrega es un proyecto presentable en vivo, no un informe.
- **S4** — «que muestre ambos para el 5 el analizador de phishing y honeypot casero que
  hago»: esta actividad muestra **las dos** herramientas; esta es la segunda.
- **S5** — «honeypot casero»: trampa propia que acepta cualquier credencial y **registra
  cada intento y cada orden** del atacante, sin tocar ningún sistema real.
- **S6** — La demo en vivo es reproducible y funciona **sin internet**: un script levanta el
  honeypot, ejecuta un ataque simulado contra el honeypot propio y muestra el registro.
- **S7** — Cero dependencias externas (solo `std`): `cargo build --release` produce un
  ejecutable que funciona sin internet y sin instalar nada.
- **S8** — Material de presentación: guion con tiempos, diapositivas y guía de ensayo.
- **S9** — Marco legal y ética: **loopback obligatorio**, credenciales sintéticas en la
  demo y advertencia visible en la salida del programa.

## Tasks

| ID | Specs | Tarea | Commit |
| --- | --- | --- | --- |
| T1 | S1, S7 | Crate propio en la raíz del repositorio, `Cargo.toml` autónomo | `chore: bootstrap` |
| T2 | S5, S9 | Trampa tipo SSH, shell falso, log JSONL con marca de tiempo | `feat(honeypot): fake SSH trap with JSONL logging` |
| T3 | S5, S6 | Trampa web de login, visor `show` y cliente de ataque simulado | `feat(honeypot): HTTP trap, session viewer and scripted attack` |
| T4 | S6 | Corrección del emparejamiento orden/respuesta, con prueba de regresión | `fix(honeypot): pair each command with its own answer` |
| T5 | S8 | Guion, diapositivas, guía de ensayo, script de demo y README | `docs: presentation script, slides and rehearsal guide` |
| T6 | S1–S9 | Verificación final: `cargo test`, `clippy`, `fmt`, ensayo sin internet | `chore: final verification` |

## Contrato técnico

**Subcomandos**

```
honeypot serve  [--bind 127.0.0.1] [--ssh-port 2222] [--http-port 8080] [--log RUTA]
honeypot show   [--log RUTA] [--json]
honeypot attack [--target 127.0.0.1:2222] [--passwords N]
```

**Guardas**: `serve` y `attack` solo aceptan direcciones de loopback; no existe bandera
para saltarse la guarda.

**Registro**: JSONL, un objeto por línea, con `ts` (ISO-8601 UTC calculada a mano, sin
`chrono`), `service`, `event`, `peer`, `session` y los campos del evento.

**Trampa tipo SSH**: banner `SSH-2.0-OpenSSH_9.6 Ubuntu-3ubuntu13`, prompt `login:`, prompt
`Password:`, dos rechazos (`Permission denied, please try again.`) y aceptación de la
tercera credencial; después, shell falso con prompt `root@victima:~# `.

**Trampa web**: `GET /` devuelve el login falso; `POST /login` registra `user` y `password`
y responde siempre «Sesión iniciada», sin autenticar a nadie; cualquier otra ruta responde
404 y queda registrada.

## Log

- **L1** (2026-11-20, señor) — «Dame proyecto de ciberseguridad para poder mostrar en una
  actividad el 5 de diciembre».
- **L2** (2026-11-20, señor) — «que muestre ambos para el 5 el analizador de phishing y
  honeypot casero que hago».
- **L3** (2026-11-20, señor) — Decide: **los dos proyectos, en Rust**.
- **L4** (2026-11-20, Kairos) — La trampa SSH es una **emulación de banner y prompt en
  texto**, documentada como tal en README y guion: no es un servidor SSH real.
- **L5** (2026-11-20, Kairos) — El cliente `attack` quedó limitado a loopback, igual que
  `serve`, porque este material solo puede usarse contra el laboratorio propio.
- **L6** (2026-11-20, Kairos) — Defecto real encontrado por las pruebas: el cliente leía el
  prompt pendiente antes de la respuesta, así que el transcript salía desfasado una orden.
  Corregido y cubierto por una prueba de regresión.
- **L7** (2026-11-20, Kairos) — Repositorio separado con el nombre de la actividad, para
  que cada mitad se pueda revisar, publicar y defender por separado.
- **L8** (2026-11-21, Kairos) — El repositorio hermano `analizador-phishing` ya está
  publicado con su demo en vivo (<https://runer0101.github.io/analizador-phishing/>); se
  añadió ese enlace a las referencias de este repositorio y al guion completo.
- **L9** (2026-11-21, Kairos) — El señor pergunta por qué este proyecto no estaba en GitHub:
  estaba publicado solo el analizador. Se prepara la publicación del honeypot con licencia
  MIT, workflows de CI y de release (cinco binarios con sus sumas SHA-256) y el README con
  la sección de descargas, igual que en el repositorio hermano.
