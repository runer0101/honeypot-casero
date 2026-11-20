# Guion — Honeypot casero (parte 2 de la actividad)

Tiempo: **5:30 a 12:00** de los 12 minutos de la exposición. La primera mitad (el analizador
de phishing) está en el repositorio `analizador-phishing`, y el guion completo de las dos
partes está en [`PRESENTACION.md`](PRESENTACION.md).

Los comandos son los mismos que usa `scripts/demo.sh`.

---

## 5:30 — 8:30 · El honeypot casero

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

Señalar el `download_attempt`: «esto es lo que un analista busca en la mañana siguiente:
qué descarga, desde dónde, con qué credenciales disqueó.

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
| El servidor no levanta | `cat logs/honeypot-servidor.log` para ver el error |
| Se cortó la demo en vivo | video de respaldo (`docs/ENSAYO.md`, punto 4) |
