# Plan de demo en vivo (y plan B)

Paso a paso de las tres demostraciones y qué hacer cuando el aula falla. Todo el material
funciona **sin internet**: la demo web es un extra, no una dependencia.

Complementos: [`GUION.md`](GUION.md) (qué decir y cuándo) ·
[`CHECKLIST-EXPOSICION.md`](CHECKLIST-EXPOSICION.md) (los diez puntos del día) ·
[`ENSAYO.md`](ENSAYO.md) (ensayo en casa).

---

## Antes de salir (cinco minutos)

```bash
# 1. Binarios en el pendrive, con permiso de ejecución
cargo build --release
cp target/release/phishing-analyzer target/release/honeypot /media/USB/
cd /media/USB && chmod +x phishing-analyzer honeypot

# 2. La demo corre SIN internet (comprobación real)
unshare -rn bash -c 'ip link set lo up; scripts/demo.sh'

# 3. Los puertos que usará la trampa están libres
ss -ltn | grep -E ':(2222|8080) ' || echo "libres"

# 4. Diapositivas en PDF por si el aula no abre Markdown
ls docs/DIAPOSITIVAS.md docs/GUION.md
```

Y en el pendrive, además: el **video de respaldo** (dos minutos: la demo del analizador y
el ciclo del honeypot), las diapositivas en PDF y los binarios de la release.

---

## Demo 1 · Analizador en la terminal (3 minutos)

```bash
./target/release/phishing-analyzer --demo
```

Qué debe verse: los cinco casos con su puntaje y su veredicto (**ALTO**, **MEDIO**,
**BAJO**).

```bash
./target/release/phishing-analyzer "http://paypa1.com/login/verify" --explain
```

Qué debe verse: las tres señales con su código y su puntaje, y debajo el bloque
«Qué significa / Qué hacer» de cada una.

```bash
./target/release/phishing-analyzer --json "http://paypa1.com/login/verify"
```

Qué debe verse: una sola línea JSON con `url`, `dominio`, `nivel`, `puntos` y `senales`.

**Si el comando no está compilado**, se compila en el momento (10–20 s) o se usa el binario
del pendrive:

```bash
/media/USB/phishing-analyzer --demo
```

---

## Demo 2 · Analizador en el navegador (1 minuto)

```bash
xdg-open https://runer0101.github.io/analizador-phishing/
```

Escribir `http://paypa1.com/login/verify` y pulsar el botón de analizar.

**Qué decir:** «El análisis ocurre en el navegador del visitante, con WebAssembly; el enlace
no sale de su equipo. Es la misma biblioteca del programa de terminal.»

**Si no hay internet o el site's bloqueado:** se salta esta demo sin perder nada. La
terminal ya mostró lo mismo; la web es el extra.

---

## Demo 3 · Honeypot (1 minuto)

```bash
./scripts/demo.sh
```

El script hace toda la secuencia: levanta la trampa en `127.0.0.1`, ejecuta el atacante
simulado, muestra la salida de la trampa y el resumen del registro.

Lo que hay que señalar, en orden:

1. La entrada del atacante: `root` con contraseñas típicas; las dos primeras se rechazan y
   la **tercera se acepta**.
2. Las órdenes: `uname -a`, `whoami`, `id`, `ls`, `cat /etc/passwd` y un `wget`.
3. La descarga simulada: `Saving to: 'payload.sh'` contra `198.51.100.7`.
4. El resumen: sesión, credenciales, órdenes, descargas y estadísticas.

**Si el script tarda**, la alternativa es hacerlo a mano en dos terminales:

```bash
# Terminal 1 — la trampa
./target/release/honeypot serve --bind 127.0.0.1 --ssh-port 2222 --http-port 8080 --log logs/honeypot.jsonl

# Terminal 2 — el atacante
./target/release/honeypot attack --target 127.0.0.1:2222

# Terminal 1 o 3 — el resumen
./target/release/honeypot show --log logs/honeypot.jsonl
```

---

## Plan B · Cuando el aula falla

| Problema | Qué hacer | Qué decir |
| --- | --- | --- |
| **El proyector no enciende o no lee el PDF** | Diapositivas impresas o segunda máquina; si no hay nada, hablar de pie | «Voy a explicarles las dos herramientas con la terminal solamente.» |
| **No hay internet** | Se salta la demo web y se sigue con la terminal | «La demostración en el navegador necesita internet; esta no. Por eso la hice así.» |
| **El WiFi del auditorio bloquea GitHub Pages** | Igual: demo web fuera, terminal dentro | «Por suerte la parte importante corre en mi máquina.» |
| **El equipo del aula no tiene Rust** | Binarios de la release v0.3.0 desde el pendrive | «Este binario es el mismo que está publicado con su suma SHA-256.» |
| **El puerto 2222 o 8080 está ocupado** | `SSH_PORT=32222 HTTP_PORT=38080 ./scripts/demo.sh` | — |
| **No se ve el color** | `NO_COLOR=1 ./scripts/demo.sh` | — |
| **La demo se cuelga o da error** | `Ctrl+C`, al video de respaldo | «Aquí está el video con la misma demostración.» |
| **Se va de tiempo** | Saltar la demo web y la tercera recomendación | — |

### Binarios de la release v0.3.0 (funcionan 100 % sin internet)

```bash
# Linux x86-64
curl -LO https://github.com/runer0101/analizador-phishing/releases/download/v0.3.0/phishing-analyzer-linux-x86_64
curl -LO https://github.com/runer0101/analizador-phishing/releases/download/v0.3.0/phishing-analyzer-SHA256SUMS.txt
sha256sum -c phishing-analyzer-SHA256SUMS.txt   # verificar la descarga
chmod +x phishing-analyzer-linux-x86_64
./phishing-analyzer-linux-x86_64 --demo
```

Lo mismo para el honeypot:

```bash
curl -LO https://github.com/runer0101/honeypot-casero/releases/download/v0.3.0/honeypot-linux-x86_64
curl -LO https://github.com/runer0101/honeypot-casero/releases/download/v0.3.0/honeypot-SHA256SUMS.txt
sha256sum -c honeypot-SHA256SUMS.txt
chmod +x honeypot-linux-x86_64
./honeypot-linux-x86_64 serve --bind 127.0.0.1 --ssh-port 2222 --http-port 8080 --log logs/honeypot.jsonl
```

> Si **tampoco** hay internet en ese momento, esos dos archivos se copiaron antes al
> pendrive: por eso el plan B no depende de la red en ningún momento.

### Los tres recursos que salvan una exposición

1. **El video de respaldo** (dos minutos, en el pendrive y en la nube).
2. **Los binarios sueltos** en el pendrive, sin depender de Rust ni de la red.
3. **Las diapositivas en PDF**, no solo en Markdown.
