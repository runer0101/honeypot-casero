# Checklist del día — INJECTCONx01 (5 de diciembre, Salón Auditorio UNIFRANZ)

Diez puntos, verificables en cinco minutos. Márcalos con una línea al lado.

## En casa, antes de salir

- [ ] **1. Binarios en el pendrive.** Deben estar los dos y con permiso de ejecución.
      ```bash
      cargo build --release && cp target/release/phishing-analyzer target/release/honeypot /media/USB/
      cd /media/USB && chmod +x phishing-analyzer honeypot
      ```
- [ ] **2. La demo corre SIN internet.** Apaga el wifi y ejecútala: tiene que funcionar igual.
      ```bash
      unshare -rn bash -c 'ip link set lo up; scripts/demo.sh'
      ```
- [ ] **3. Los dos repositorios están limpios y con el código completo.**
      ```bash
      git status --short && git log --oneline -1
      ```
- [ ] **4. Video de respaldo grabado** (dos minutos: la tabla del analizador y el ciclo del
      honeypot) y guardado **en el pendrive y en la nube**.
      ```bash
      asciinema rec demo.cast -c "scripts/demo.sh"   # o la grabación de pantalla
      ```
- [ ] **5. Diapositivas en PDF** (por si el equipo del aula no abre Markdown) y también las
      diapositivas en Markdown por si hay que editarlas en el momento.
      ```bash
      ls docs/DIAPOSITIVAS.md docs/PRESENTACION.md
      ```

## En el salón, antes de exponer

- [ ] **6. Proyector y sonido.** Llegar a las **08:10**: el turno empieza a las 08:30 y la
      sala se llena. Probar con las diapositivas en PDF, no con el Markdown.
- [ ] **7. Puertos libres.** La trampa usa 2222 y 8080. Si están ocupados, se cambian:
      ```bash
      SSH_PORT=32222 HTTP_PORT=38080 scripts/demo.sh
      ```
- [ ] **8. Legibilidad.** Probar con color y, si el proyector no se ve bien, sin color:
      ```bash
      NO_COLOR=1 scripts/demo.sh
      ```
- [ ] **9. Sin red es igual.** La demo **no necesita internet**. La web del analizador es un
      extra: si hay conexión, se abre en el navegador; si no, se sigue con la local.
      ```bash
      # comprobación rápida de que la red no estorba
      curl -s -o /dev/null -w '%{http_code}\n' https://runer0101.github.io/analizador-phishing/
      ```
- [ ] **10. Ensayo cronometrado de 12 minutos.** Con cronómetro y alguien mirando: si se
      pasa de 12 minutos, se recorta la parte de las diez recomendaciones, nunca la demo.
      ```bash
      time scripts/demo.sh
      ```

## Plan B de un vistazo

| Si falla… | Entonces… |
| --- | --- |
| El proyector no abre Markdown | Diapositivas en PDF |
| El puerto está ocupado | `SSH_PORT=32222 HTTP_PORT=38080 scripts/demo.sh` |
| Se ve mal el color | `NO_COLOR=1 scripts/demo.sh` |
| El equipo no tiene Rust | Binarios del pendrive |
| La red se cae | La demo local no la necesita |
| Se corta la demo | Video de respaldo (punto 4) |
