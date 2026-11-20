# Presentación completa — actividad de ciberseguridad (12 minutos)

Guion de la exposición tal como se va a dictar: las dos herramientas de la actividad. Este
documento está duplicado en los dos repositorios para que la presentación completa esté a
mano en cualquiera de los dos:

- [`analizador-phishing`](../analizador-phishing) — el detector de enlaces de phishing.
- [`honeypot-casero`](../honeypot-casero) — la trampa que registra al atacante.

Regla de oro: **el público tiene que ver funcionando las dos herramientas**. Todo lo
demás es contexto. Los comandos de esta guía son los mismos que usan los scripts
`scripts/demo.sh` de cada repositorio.

Ensayo previo: `docs/ENSAYO.md` de cada repositorio. Plan B: el video de respaldo.

---

## 0:00 — 1:00 · Portada

**Diapositiva 1.**

> «Voy a mostrar dos herramientas que escribí en Rust para esta actividad: una detecta
> enlaces de phishing **sin visitarlos** y la otra es un honeypot que **graba lo que hace
> un atacante** cuando entra. Las dos corren en mi máquina, sin internet, y están escritas
> sin usar ninguna biblioteca externa: solo la biblioteca estándar de Rust.»

---

## 1:00 — 2:30 · El problema

**Diapositiva 2.**

> «El phishing sigue funcionando porque ya no necesita software: necesita que **yo** tenga
> prisa y confianza. Un enlace como `paypa1.com` se ve como PayPal si uno mira rápido: es la
> "l" cambiada por un "1".»

> «Hay dos formas de defender. Una es analizar el enlace **antes** de que la persona lo
> abra. La otra es **observar al atacante** cuando entra, para saber qué busca. Eso es
> justamente lo que hacen las dos herramientas que les voy a mostrar.»

---

## 2:30 — 4:30 · Herramienta 1: el analizador de phishing

**Ejecutar:**

```bash
target/release/phishing-analyzer --demo
```

**Diapositiva 3.** Mientras corre, explicar en voz alta:

> «El analizador **no abre el enlace**. No pide DNS, no hace peticiones, no sale a
> internet. Toma el texto del enlace y le aplica once reglas, cada una con un puntaje. Al
> final suma los puntos: cinco o más es riesgo alto, tres o cuatro medio, menos de tres
> bajo.»

Señalar en pantalla, uno por uno:

| Lo que se ve | Lo que significa |
| --- | --- |
| `+3 typosquat` | el «1» de `paypa1` imita la «l» de PayPal |
| `+3 brand_impersonation` | dice "paypal" pero el dominio real termina en `.com` |
| `+2 ip_host` | un login de WordPress servido desde una IP cruda |
| `+1 hook_words` | palabras de gancho: `login`, `verify`, `clave`… |

> «Fíjense en el último caso: `bancounion.com.bo` **es** un sitio real, y el analizador
> le da un punto porque la ruta dice "verificacion-clave". Eso es un **falso positivo** y
> se lo voy a reconocer ahora mismo, porque un detector que nunca se equivoca no existe.»

**Diapositiva 4 (opcional, 20 s):** mostrar la salida JSON.

```bash
target/release/phishing-analyzer --json "http://paypa1.com/login/verify"
```

> «También lo puedo usar como herramienta: esto devuelve JSON y se puede alimentar a otro
> sistema, como un antivirus corporativo o un filtro del navegador.»

---

## 4:30 — 5:30 · Lo que el analizador no puede hacer

**Diapositiva 5.**

> «Tres límites, y los digo antes de que me los pregunten:»

1. «Falsos positivos: un sitio legítimo con palabras de gancho en la ruta suma puntos.»
2. «Falsos negativos: un phishing con dominio nuevo y limpio puede salir en verde.»
3. «No mira la página, solo la dirección. Un sitio de phishing dentro de `facebook.com`
   real no lo detecta.»

> «Por eso la conclusión correcta no es "esto es phishing", sino "esto **merece revisión
> humana"». La herramienta ayuda, la persona decide.»

---

## 5:30 — 8:30 · Herramienta 2: el honeypot

**Ejecutar (una terminal para la trampa, otra para el atacante):**

```bash
target/release/honeypot serve --bind 127.0.0.1 --ssh-port 2222 --http-port 8080 --log logs/honeypot.jsonl
```

En otra terminal:

```bash
target/release/honeypot attack --target 127.0.0.1:2222
```

**Diapositiva 6.** Mientras corre:

> «El honeypot es una **trampa**. Tiene la apariencia de un servidor SSH: mismo banner,
> mismo "login:", mismo "Password:". La diferencia es que **todo lo que se hace aquí
> queda registrado**, y que la máquina no existe: las respuestas son inventadas.»

> «Fíjense en las dos primeras credenciales: el honeypot las **rechaza**. Y la tercera la
> acepta. ¿Por qué? Porque si bloqueara al atacante no sabríamos qué viene después. Un
> honeypot no es una barrera, es una **cámara**.»

> «Ahora el atacante está "dentro". Manda `uname -a`, `cat /etc/passwd`, y un `wget` de un
> archivo malicioso. Todo queda anotado con la hora exacta.»

**Ejecutar también (10 s, si hay tiempo):**

```bash
target/release/honeypot show --log logs/honeypot.jsonl
```

> «Y este es el resumen que le dejaría a un jefe: una sesión, las credenciales que se
> intentaron y las órdenes ejecutadas.»

---

## 8:30 — 9:30 · Lo que aprendemos del registro

**Diapositiva 7.**

> «Del registro salen tres cosas que valen para un equipo de seguridad:»

1. «**Qué credenciales** usa el atacante: aquí `root` con contraseñas típicas. Eso dice
   qué hay que cambiar y qué MFA activar.»
2. «**Qué busca**: leer `/etc/passwd` es buscar accesos; el `wget` es la fase de
   descarga, que es cuando empieza el daño real.»
3. «**Cuándo**: con la hora exacta se puede correlacionar con otros registros del
   servidor y ver si hubo más intentos.»

---

## 9:30 — 10:30 · Defensa: tres recomendaciones

**Diapositiva 8.**

1. **No confíe en el dominio, confíe en el contexto.** Un dominio que imita una marca, con
   palabras de gancho y sin HTTPS, merece revisión aunque "se vea" como el banco.
2. **Consultas parametrizadas y MFA.** Del lado del servidor: ningún dato de entrada llega
   concatenado a una consulta; del lado del usuario, el segundo factor corta la mayoría de
   los ataques automatizados.
3. **Reglas de salida para el correo.** Que el filtro de correo marque los enlaces
   acortados y los remitentes que no coinciden con el dominio real.

---

## 10:30 — 11:15 · Legal, límites y trabajo futuro

**Diapositiva 9.**

> «Todo esto corre en `127.0.0.1`. El programa **se niega** a escuchar en otra dirección, y
> el "atacante" de la demostración es un script del propio proyecto. No se escanea a nadie,
> no se toca a nadie: es un laboratorio autorizado.»

> «Y lo que faltaría: persistir el registro en una base de datos, mandar avisos cuando un
> intento viene de una IP nueva, y un panel web con las sesiones.»

---

## 11:15 — 12:00 · Cierre

**Diapositiva 10.**

> «Dos herramientas propias, en Rust, sin dependencias externas, que funcionan sin
> internet: una **detecta** el phishing antes de que llegue a la persona y la otra
> **observa** al atacante cuando entra. El código y el guion están en los dos
> repositorios.»

> «Gracias. ¿Preguntas?»

---

## Plan B (si algo falla en el aula)

| Problema | Qué hacer |
| --- | --- |
| El puerto 2222 está ocupado | `SSH_PORT=32222 HTTP_PORT=38080 scripts/demo.sh` |
| No hay color | `NO_COLOR=1 scripts/demo.sh` |
| El equipo del aula no tiene Rust | llevar los binarios en un pendrive y ejecutar el video |
| Se cortó la demo en vivo | video de respaldo (`docs/ENSAYO.md`, punto 4) |
