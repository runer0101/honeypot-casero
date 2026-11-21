# Banco de preguntas y respuestas (jurado)

Cinco preguntas muy probables, con la **respuesta corta** (la que cabe en 20 segundos) y la
**respuesta completa** (la que da puntos). En las dos versiones: primero el límite, luego
la solución. Nunca defender más de lo que la herramienta hace.

---

## 1. «¿Por qué no usan simplemente VirusTotal o una lista negra de dominios?»

**Respuesta corta:**
> «Una lista negra sabe lo que **ya** fue reportado. Ours detecta lo que **parece** phishing
> desde el primer día, sin conexión y sin enviar el enlace a nadie.»

**Respuesta completa:**

- Una lista negra es una **consulta de reputación**: pregunta «¿alguien ya reportó esto?».
  Eso tiene dos límites y una dependencia:
  1. **El phishing nuevo no está en la lista.** El 90 % de las campañas usa dominios
     recién registrados; el día que aparecen, ninguna blacklist los conoce todavía.
  2. **Hay que enviar el enlace a un tercero.** Al consultar VirusTotal, el enlace —
     que puede contener datos personales o un token— sale de la red de la persona y queda
     registrado por un servicio de terceros. Para una persona que analiza un enlace
     sospechoso, eso ya es una fuga.
- Nuestra herramienta es **estructural y explicable**: no necesita saber si el dominio es
  conocido, mira cómo está construido. Por eso detecta un `bcp-seguro.com.bo` el mismo día
  que aparece, y por eso puede decir **por qué** lo marcó.
- Además **funciona sin internet** y sin enviar nada: es la diferencia entre una alerta y
  una fuga de datos.
- **Límite honesto:** el analizador no sabe si un dominio con forma sospechosa es
  real o falso. Por eso el veredicto es «merece revisión humana», no «esto es phishing».
  Y por eso **las dos cosas son complementarias**: la reputación agrega lo que la forma no
  puede ver.

---

## 2. «¿Por qué eligieron Rust y no Python o Go?»

**Respuesta corta:**
> «Por una razón práctica: el mismo código tiene que correr en el navegador. Python no
> compila a WebAssembly; Rust sí. Y sin dependencias, la release es un archivo.»

**Respuesta completa:**

- **Una sola base de código, tres destinos.** La biblioteca del analizador se compila a
  binario de terminal (`cargo build`) y a WebAssembly (`--target wasm32-unknown-unknown`)
  **sin cambiar una línea**: la demo web es el mismo motor, no una reimplementación. En
  Python, el camino a WebAssembly (Pyodide, Transpiled Python) es frágil y pesado; en Go
  es posible, pero con `syscall/js` y un ejecutable enorme —una experiencia muy distinta
  de «leer un archivo y ya está».
- **Cero dependencias externas.** Con Python habría que entregar un `requirements.txt`, un
  entorno virtual y una instalación; con Go, un binario de 2 MB por nada. Con Rust: la
  biblioteca estándar y nada más. Eso permite clonar, compilar y usar la herramienta en un
  laboratorio sin red y sin mantenimiento.
- **Una release multiplataforma real.** Los cinco binarios (Linux x86-64 y ARM64, macOS
  Intel y Apple Silicon, Windows) salen del mismo `cargo build --release --target ...`, con
  sumas SHA-256, sin scripts propios de empaquetado.
- **Seguridad sin garbage collector.** Es código que procesa entradas **hostiles** (un
  enlace es entrada no confiable): en Rust, la familia de errores de memoria no existe.
- **Herramientas de oficio.** `cargo test`, `cargo clippy -- -D warnings` y `cargo fmt`
  están en el CI: el estilo y los errores comunes se detectan antes de la exposición, no
  durante.
- **Límite honesto:** Python se habría escrito más rápido y Go se habría distribuido
  con menos ceremonia. Rust se pagó con el tiempo de aprendizaje, a cambio de la demo web
  y de las releases limpias.

---

## 3. «El honeypot SSH no hace un handshake criptográfico real, ¿no es eso una limitante grave?»

**Respuesta corta:**
> «Sí, lo es, y es deliberado: es una trampa de **baja interacción**. El cliente real de
> OpenSSH no llegaría al «Password:»; por eso la demo la hace el propio script. Es el
> límite conocido, no un error.»

**Respuesta completa:**

- **La limitación, dicha sin rodeos.** El honeypot emula el banner (`SSH-2.0-...`) y el
  diálogo `login:` / `Password:` **en texto**, pero no implementa el transporte SSH: sin
  *key exchange*, sin criptografía, sin canal seguro. En consecuencia:
  - un cliente real como `ssh -p 2222 usuario@127.0.0.1` **falla en el handshake** y nunca
    ve el prompt;
  - quien interactúa de verdad es un script como `nc`, o una persona desde otra terminal.
- **Qué gana y qué pierde.** Se gana: un programa diminuto, sin dependencias, auditable y
  que se puede explicar en doce minutos. Se pierde: la fidelidad frente a clientes
  automatizados reales, que detectan el emulado y se van.
- **Cómo se mitiga hoy.** El registro sigue siendo útil: captura el intento de acceso, el
  usuario, las contraseñas, la sesión de órdenes y los tiempos. Para un laboratorio
  educativo y una demostración, esa información es el objetivo.
- **Qué se endureció desde la v0.2.0** (y por qué no cambia la conclusión): la sesión
  tiene ahora un tope **absoluto** además del de inactividad, las líneas de más de 8 KiB
  cierran la sesión, y hay un timeout de escritura. Antes, un atacante que mandaba un byte
  cada segundo podía mantener la sesión abierta indefinidamente.
- **Trabajo futuro, en orden.** 1) Un transporte SSH mínimo (hasta *key exchange* por
  *curve25519-sha256* y un canal con *cipher* simulado) para que un cliente real entre.
  2) Migrar a un proyecto como **Cowrie**, que ya implementa el protocolo y trae una
  comunidad: a cambio de dependencias y de una superficie de ataque mucho mayor.
  3) Empaquetarlo como contenedor con `systemd` y una IP de pruebas documentada.
- **La conclusión honesta:** es una herramienta de **baja interacción** y su valor es
  didáctico y de laboratorio, no de producción. Para un honeypot de producción con
  atacantes reales, el camino es Cowrie o similar.

---

## 4. «Noté que una IP privada (192.168.x.x) activa la alerta de «IP en lugar de dominio». ¿Es un falso positivo?»

**Respuesta corta:**
> «En el contexto de un enlace que llega por correo o WhatsApp, no: es una señal legítima.
> En una red interna, sí, y es un límite conocido de un analizador que no conoce su red.»

**Respuesta completa:**

- **Qué hace la regla.** La señal `ip_dominio` (+2 puntos) detecta que el enlace apunta a
  una dirección IP en lugar de a un nombre de dominio. Se activa también con las formas
  numéricas que el navegador acepta: `http://2130706433/`, `http://0x7f000001/` o
  `http://017700000001/` — el mismo 127.0.0.1 escrito de tres maneras.
- **Por qué no es un falso positivo en el uso previsto.** El analizador está pensado para
  enlaces que llegan de fuera: un correo, un SMS, un mensaje de WhatsApp. Un enlace
  público que apunta a una IP cruda es, por definición, sospechoso: no hay nombre que
  pueda registrar a nadie, no hay certificado y no hay a quién reclamar. En el caso de la
  demo, `http://192.168.56.101/wp-login.php` da **MEDIO** a propósito.
- **Dónde sí molesta.** Dentro de una red interna, un enlace legítimo a `192.168.1.1`
  dispara la señal y el veredicto sube sin motivo. **El analizador no conoce la red en la
  que se usa**: no tiene ni puede tener esa información si se ejecuta en el navegador del
  visitante.
- **Cómo se matiza.** Tres opciones, en orden de coste:
  1. **Uso**: el analizador se aplica a enlaces externos; los internos se revisan a mano.
  2. **Configuración**: una lista de rangos internos excluidos (`10.0.0.0/8`, `172.16.0.0/12`,
     `192.168.0.0/16`, `127.0.0.0/8`) que reste esa señal. Es un cambio pequeño y es la
     primera mejora pendiente.
  3. **Contexto**: que el informe diga de dónde viene el enlace y ajuste el peso según
     sea interno o externo.
- **La conclusión honesta:** la regla es correcta para el caso de uso y ruidosa para otro.
  Es exactamente el tipo de límite que conviene decir en voz alta antes de que lo pregunten.

---

## 5. «¿Es ético/legal correr un honeypot?»

**Respuesta corta:**
> «Un honeypot es legal en un laboratorio propio y sin toxicidad. El nuestro tiene cuatro
> guardas: solo loopback, credenciales sintéticas, un atacante propio y una IP reservada
> para documentación.»

**Respuesta completa:**

- **El principio.** Un honeypot no es un ataque: es un servicio que **acepta** conexiones
  para **registrar** a quien entra. No explota nada, no accede a cuentas ajenas y no
  necesita convencer a nadie. La preocupación legal y ética aparece en otros dos casos:
  - si se expone a internet sin avisar, se está capturando tráfico de terceros y, en
    muchos países, hay que avisar a la autoridad de protección de datos y a los propios
    visitantes;
  - si se empieza a **actuar** sobre el atacante (devolver exploits, usar sus comandos
    para entrar a otros sistemas), eso ya es otra cosa y ya no es un honeypot.
- **Las cuatro guardas de esta herramienta:**
  1. **Solo loopback.** `serve` y `attack` **rechazan** cualquier dirección que no sea
     `127.0.0.1` o `::1`. Y la comprobación está **dentro de la función que abre el
     socket**, no solo en la CLI: quien use la biblioteca como una dependencia tampoco
     puede enlazar `0.0.0.0`.
  2. **El atacante es nuestro.** La demo usa un script del propio proyecto; no hay
     escaneo, no hay terceros, no hay botnets.
  3. **Credenciales sintéticas.** No hay cuentas reales que probar ni datos reales que
     registrar: `root`/`123456` son cadenas inventadas.
  4. **Una IP reservada para documentación.** La descarga falsa apunta a
     `198.51.100.7`, del bloque `TEST-NET-2` de la **RFC 5737**, que existe justamente
     para este uso. **Nunca se contacta**: el tamaño del archivo es un número constante.
- **El registro también es un dato personal.** Un honeypot real guarda IP, hora y
  comandos: eso exige un aviso legal, un tiempo de conservación corto y acceso restringido.
  En un laboratorio local, el registro es de uno mismo.
- **La conclusión honesta:** lo que se presenta es un **laboratorio educativo** en la
  máquina del expositor, con datos inventados, sin red y sin terceros. Lo que **no** se
  presenta —ni se recomienda— es montar esto en producción sin autorización, sin aviso y
  sin una política de conservación de datos.

---

## 6. «Noté que `airbnb.com` me daba positivo. ¿Es un falso positivo?»

**Respuesta corta:**
> «Lo era, y por eso lo cambiamos en la v0.3.0: la marca tiene que aparecer como palabra
> completa o al principio de la etiqueta. Antes cualquier subcadena servía, y «bnb» se
> encontraba dentro de «airbnb».»

**Respuesta completa:**

- **Qué pasaba.** La regla de «usa el nombre de una marca» comparaba la marca con la
  etiqueta completa buscando la marca como **subcadena**. Con la marca «bnb» (Banco
  Nacional de Bolivia) eso hacía que `airbnb.com` se marcara como `marca_falsa` con tres
  puntos: un sitio legítimo, con veredicto medio.
- **Cómo se corrigió.** Ahora la marca tiene que aparecer como **palabra completa**
  («paypal-seguro», «bcp-verificar») o **al principio** de una etiqueta («paypalseguro»).
  Con eso `airbnb.com`, `pineapple.com` y `www.bancounion.com.bo` salen limpios, y en
  cambio `paypal-seguro.com`, `bcp-verificar.com` y `bnb-seguro.com` se siguen detectando.
  Hay una prueba que lo fija, para que no vuelva a pasar.
- **El coste de la corrección, dicho en voz alta:** un dominio que **pega** la marca al
  final (`mypaypal.com`) hoy no se marca. Se aceptó ese límite a propósito: aceptar el
  final obligaría a marcar `pineapple.com` como si fuera `apple`, y un falso positivo sobre
  un sitio legítimo se ve mucho más que un falso negativo difícil de imagining.
- **La lección, que es la misma de siempre:** un detector que nunca se equivoca no existe.
  Lo que importa es que cada acierto y cada error se pueda explicar.

---

## Preguntas que también conviene tener preparadas

**«¿Qué pasa si alguien intenta tumbar la trampa?»**
> «La trampa tiene cuatro límites: 10 credenciales por sesión, 5 minutos de sesión (tope
> absoluto, no solo de inactividad), líneas de 8 KiB como máximo y un timeout de escritura.
> El que se queda callado, el que manda una línea infinita y el que abre la conexión y no
> lee, cierran su sesión y quedan anotados en el registro.»


**«¿Qué pasa si el phishing usa un dominio real, dentro de `facebook.com`?»**
> «No lo detecta: el analizador solo mira la dirección, no la página. Detectar eso exige
> revisar el contenido, y revisar contenido automáticamente tiene su propio problema:
> los falsos positivos. Es un límite declarado, no un descuido.»

**«¿Y los falsos negativos?»**
> «Un phishing con dominio recién registrado, limpio y con HTTPS sale en verde. Por eso el
> veredicto correcto es «merece revisión humana». La herramienta ayuda; la persona decide.»

**«¿Por qué no usaste una base de datos o un servidor web?»**
> «Para que la demo no dependa de nada: un archivo JSONL se lee con `cat` y con
> `honeypot show`, y se puede versionar, copiar y analizar con cualquier herramienta.
> Guardarlo en una base de datos es trabajo futuro, no una necesidad de la v0.2.0.»

**«¿Cuánto cuesta upkeep?»**
> «Cero dependencias significa cero actualizaciones de seguridad que seguir. Las reglas se
> editan en archivos de texto plano dentro de `datos/`, sin recompilar nada.»
