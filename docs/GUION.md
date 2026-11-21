# Guion de la exposición — 12 minutos

**Narrativa central:** «Defendemos el phishing desde dos frentes: **antes del clic**
(el analizador) y **después del clic** (el honeypot)».

Este documento está duplicado en los dos repositorios para que el guion completo esté a
mano en cualquiera de los dos:

- [`analizador-phishing`](../analizador-phishing) — detecta enlaces de phishing **sin
  visitarlos**.
- [`honeypot-casero`](../honeypot-casero) — registra lo que hace el atacante cuando entra.

Materiales relacionados: [`DEMO.md`](DEMO.md) (paso a paso y plan B) ·
[`Q-A.md`](Q-A.md) (preguntas del jurado) · [`DIAPOSITIVAS.md`](DIAPOSITIVAS.md) ·
[`CHECKLIST-EXPOSICION.md`](CHECKLIST-EXPOSICION.md).

**Regla de ritmo:** si algo se alarga, se recorta la explicación (min 8–10) y **nunca** las
demos (min 4–7 y 10–11). Si la demo falla, se sigue con el video de respaldo.

| Minuto | Bloque | Diapositivas | En pantalla |
| --- | --- | --- | --- |
| 0–2 | Gancho y problema | 1–2 | — |
| 2–4 | Frente 1: el analizador | 3–4 | — |
| 4–7 | **Demo en vivo**: analizador en la terminal | 3 | `phishing-analyzer` |
| 7–8 | **Demo en vivo**: analizador en el navegador | 3 | navegador |
| 8–10 | Frente 2: el honeypot | 6–7 | — |
| 10–11 | **Demo en vivo**: honeypot | 7 | terminal |
| 11–12 | Cierre y llamado a la acción | 8–10 | — |

---

## Min 0–2 · Gancho y problema

**Diapositivas 1 y 2.** No hay demo todavía: la cara y la voz.

> «Las víctimas de phishing casi siempre sabían que el correo era sospechoso. Lo que falta
> no es conocimiento: es una herramienta que actúe **antes** del clic. Y cuando el clic ya
> pasó, falta otra que grabe **después** lo que hizo el atacante. Eso es lo que les voy a
> mostrar: dos herramientas propias, escritas en Rust, sin una sola dependencia externa, que
> funcionan sin internet.»

> «Y no es un problema ajeno. En Bolivia el vector más común no es un banco extranjero:
> es un mensaje que imita al **BCP**, al **BNB**, al **Banco Unión**, a **Mercantil Santa
> Cruz** o al **Banco Estado**, y que dice "su clave vence" o "verifique su cuenta". El
> atacante no necesita inglés: necesita que uno tenga prisa y confianza.»

> «El phishing ya no necesita software: necesita que la persona tenga prisa.»

---

## Min 2–4 · Frente 1: el analizador

**Diapositivas 3 y 4.** Señalar la tabla de las once señales.

> «El analizador **lee el enlace como texto**. No pide DNS, no abre conexiones, no sale a
> internet. Le aplica once reglas, cada una con un puntaje, y al final suma: cinco o más es
> **alto**, tres o cuatro **medio**, menos de tres **bajo**.»

> «Dos reglas son las que más importan aquí. La primera es **typosquatting**: el dominio
> imita a una marca con un cambio mínimo —una letra de más, de menos o cambiada— y se
> detecta comparando con la distancia de Damerau-Levenshtein, que también entiende los
> intercambios de letras. La segunda son los **homoglifos**: la "l" con un guion, la "a"
> cirílica, el punycode `xn--`. Para el ojo son iguales; para el analizador, no.»

> «Y las marcas que vigila son las que están aquí: BCP, BNB, Banco Unión, Mercantil Santa
> Cruz y Banco Estado, cada una con su sitio oficial. El analizador distingue las dos
> cosas: cuando el dominio **usa** el nombre de la marca (`marca_falsa`) y cuando lo
> **imita** (`typosquatting`). Un `bcp-seguro.com.bo` no es el BCP.»

---

## Min 4–7 · **Demo en vivo**: el analizador en la terminal

**Diapositiva 3 en vivo.** Tres comandos, en este orden.

```bash
# 1. Los cinco casos de la demostración
./target/release/phishing-analyzer --demo

# 2. Un caso con la explicación de cada señal
./target/release/phishing-analyzer "http://paypa1.com/login/verify" --explain

# 3. La salida en JSON, para integrarlo con otro sistema
./target/release/phishing-analyzer --json "http://paypa1.com/login/verify"
```

**Qué decir mientras corre:**

- En el comando 1: «Estos son cinco enlaces. El primero imita a PayPal con un "1" en vez de
  una "l": tres puntos solo por eso.»
- En el comando 2: «Cada señal trae su código, su puntaje y su motivo. Y con `--explain`
  además trae la explicación y qué hacer: esto es lo que un usuario final puede leer sin
  saber de ciberseguridad.»
- En el comando 3: «Y sale JSON, así que esto se puede enchufar a un filtro de correo o a
  un antivirus corporativo. No es solo una demonstration: es una pieza integrable.»

> «Un detalle que sí importa: el analizador **imita al navegador** al leer el enlace. Si el
> navegador borraría una barra sobrante o un tabulador, el analizador también, porque si no
> vería un dominio distinto al que abriría la persona.»

---

## Min 7–8 · **Demo en vivo**: el analizador en el navegador

**Diapositiva 3**, pestaña del navegador. Solo si hay internet.

```bash
xdg-open https://runer0101.github.io/analizador-phishing/   # o escríbala a mano
```

Escribir el mismo enlace: `http://paypa1.com/login/verify`.

> «Y esto no es una captura de pantalla: está publicado en GitHub Pages. Cualquiera puede
> abrirlo y el análisis ocurre **en su navegador**, con WebAssembly. El enlace que analizan
> ni siquiera sale de su equipo. Es la misma biblioteca del programa de terminal,
> compilada a WebAssembly: no es una segunda implementación, es el mismo código.»

> «Se puede enviar a alguien que no tiene Rust instalado: abre el enlace y lo prueba.»

---

## Min 8–10 · Frente 2: el honeypot

**Diapositivas 6 y 7.** Aquí va la frase clave, sin rodeos.

> «El segundo frente es **después** del clic. Y aquí hay una idea que resume toda la
> herramienta: **un honeypot no es una barrera, es una cámara**.»

> «Una barrera detiene al atacante. Una cámara lo deja pasar y lo observa. La diferencia
> es que si bloqueamos al atacante en la primera credencial, nunca sabremos qué viene
> después: qué busca, qué herramientas descarga, qué comandos ejecuta.»

> «Esta es una trampa de **baja interacción**: tiene la apariencia de un servidor SSH —
> mismo banner, mismo "login:", mismo "Password:"— pero es texto emulado, no un servidor
> SSH real. Todo lo que se hace aquí queda registrado con la hora exacta, en formato
> JSONL: las credenciales que se intentaron, las órdenes, las descargas y los clics.»

> «Y las guardas son deliberadas: solo escucha en `127.0.0.1`, el "atacante" de la demo es
> un script del propio proyecto, las credenciales son sintéticas y la descarga falsa
> apunta a una dirección reservada para documentación. Es un laboratorio, no un ataque.»

> «Del registro salen tres cosas que le sirven a un equipo de seguridad: **qué credenciales**
> usa el atacante, **qué busca** —leer `/etc/passwd` es buscar accesos— y **cuándo**, para
> correlacionarlo con otros registros.»

---

## Min 10–11 · **Demo en vivo**: el honeypot

**Diapositiva 7.** Un solo comando, porque el script ya hace la secuencia completa.

```bash
./scripts/demo.sh
```

El script levanta la trampa, ejecuta el atacante simulado y muestra el resumen. Señalar en
este orden:

1. «El atacante entra con `root` y una contraseña típica. Las dos primeras se rechazan; la
   tercera se acepta: es la cámara, no la barrera.»
2. «Mira las órdenes: `uname -a`, `whoami`, `id`, `ls`, `cat /etc/passwd`… y un `wget` de
   un archivo. Eso es reconocimiento y después descarga: el momento en empieza el daño
   real.»
3. «Y esto es lo que le dejarías a un jefe: una sesión, las credenciales intentadas, las
   órdenes y las estadísticas de usuarios e IP.»

---

## Min 11–12 · Cierre y llamado a la acción

**Diapositivas 8, 9 y 10.**

> «Tres recomendaciones concretas, y ninguna requiere instalar nada:»

1. **No confíe en el dominio, confíe en el contexto.** Un enlace que imita a un banco, con
   palabras de gancho y sin HTTPS, merece revisión aunque "se vea" como el banco.
2. **MFA y consultas parametrizadas.** Del lado del servidor, ningún dato de entrada llega
   concatenado a una consulta; del lado del usuario, el segundo factor corta la mayoría de
   los ataques automatizados.
3. **Reglas de salida para el correo.** Que el filtro marque los enlaces acortados y los
   remitentes que no coinciden con el dominio real.

> «Y con honestidad, lo que estas herramientas **no** hacen: el analizador no mira la
> página, solo la dirección; un phishing con dominio nuevo y limpio puede salir en verde; y
> la trampa es de baja interacción. Por eso la conclusión correcta no es "esto es
> phishing", sino "esto **merece revisión humana**".»

> «Defendemos el phishing desde dos frentes: antes del clic y después del clic. El código,
> la documentación y este guion están en los dos repositorios, con releases para Linux,
> macOS y Windows y sus sumas SHA-256. Y la demostración funciona sin internet: se puede
> clonar, compilar y probar en un laboratorio aislado.»

> «Gracias. ¿Preguntas?»

---

## Si el tiempo aprieta

| Sobra | Recorta |
| --- | --- |
| La demo web (min 7–8) | Comenta que existe y sigue con el cierre |
| Los comandos 2 y 3 de la demo del analizador | Deja el `--demo` y el `--explain` |
| Las tres recomendaciones | Queda solo la primera |
| El bloque 8–10 | Resume en dos frases y pasa a la demo |

**Nunca recortes:** el gancho (0–2), la frase del honeypot, la demo del honeypot y el
cierre.
