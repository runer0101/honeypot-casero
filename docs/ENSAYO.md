# Guía de ensayo — Honeypot casero

Objetivo: poder hacer la demostración **sin depender de internet** y con un video de
respaldo por si la sala falla.

## 1. Qué se necesita el día de la exposición

| Elemento | Para qué | ¿Necesita internet? |
| --- | --- | --- |
| `target/release/honeypot` | Honeypot casero | No |
| `logs/honeypot.jsonl` | Registro de la demo (se regenera en vivo) | No |
| Terminal con color | Legibilidad de la transcripción | No |
| Video de respaldo (2 min) | Si la sala falla | No |

El binario se compila **una vez antes** y se lleva en un pendrive:

```bash
cargo build --release
cp target/release/honeypot /media/USB/
```

## 2. Ensayo completo sin internet

Desconecte el cable de red o active el modo avión (la demo **no** necesita internet) y
ejecute:

```bash
scripts/demo.sh
```

Eso levanta la trampa, ejecuta el ataque simulado contra ella y muestra el registro.

Para comprobar de verdad que no hay red, se puede ensayar en un espacio de nombres
aislado:

```bash
unshare -rn bash -c 'ip link set lo up; scripts/demo.sh'
```

Prueba aislada de cada parte:

```bash
scripts/demo.sh --solo honeypot
```

## 3. Checklist antes de subir al aula

- [ ] `cargo build --release` terminó sin errores y el binario existe.
- [ ] `scripts/demo.sh` corrió completo: banner → login → password → shell → registro.
- [ ] `honeypot show` imprime la sesión con usuario, contraseña intentada y órdenes.
- [ ] El registro en crudo (JSONL) se ve bien en pantalla.
- [ ] Video de respaldo grabado (ver más abajo) y guardado **también** en el pendrive.
- [ ] Diapositivas exportadas a PDF.
- [ ] Pendrive con: el binario, las diapositivas en PDF, el video y el repositorio.
- [ ] La primera mitad de la exposición ensayada en el repositorio `analizador-phishing`.

## 4. Video de respaldo

Grabar con la herramienta del sistema (`Ctrl+Alt+Shift+R` en GNOME/KDE abre la grabación)
o con `asciinema` si lo tiene instalado:

```bash
asciinema rec demo.cast -c "scripts/demo.sh"
asciinema cat demo.cast   # reproducir
```

Grabe **la salida real**: la transcripción del atacante y el resumen del registro. Dos
minutos bastan.

## 5. Plan B si algo falla en el aula

| Fallo | Qué hacer |
| --- | --- |
| Los puertos 2222/8080 están ocupados | `SSH_PORT=32222 HTTP_PORT=38080 scripts/demo.sh` |
| La trampa no levanta | `cat logs/honeypot-servidor.log` para ver el error |
| El binario no arranca en el equipo del aula | usar el video de respaldo |
| La sala no tiene internet | no importa: la demo no usa internet |

## 6. Aviso para la exposición

El honeypot es una **actividad autorizada en un laboratorio aislado**: escucha solo en
`127.0.0.1` y el «atacante» de la demo es un programa del propio proyecto. No se escanea
ni se toca ningún sistema de terceros, y las credenciales que se ven en pantalla son
inventadas para la demo.
