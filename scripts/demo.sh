#!/usr/bin/env bash
# Demostración del honeypot casero.
#
# No necesita internet. Todo ocurre en loopback (127.0.0.1) y el "atacante" es el propio
# laboratorio: no se toca ningún sistema de terceros.

set -euo pipefail

RAIZ="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$RAIZ"

BIN="$RAIZ/target/release/honeypot"
SSH_PORT="${SSH_PORT:-2222}"
HTTP_PORT="${HTTP_PORT:-8080}"
# Ruta relativa a propósito: el log de ejemplo que se entrega no debe filtrar la
# ruta del equipo donde se generó.
LOG="${LOG:-logs/honeypot.jsonl}"
TRAZA="${TRAZA:-$RAIZ/logs/honeypot-servidor.log}"

say() { printf '\n\033[1;36m=== %s ===\033[0m\n' "$1"; }

say "Compilando (release)"
cargo build --release --quiet
echo "Listo: $BIN"

say "1. La trampa espera al atacante"
mkdir -p "$(dirname "$LOG")" "$(dirname "$TRAZA")"
rm -f "$LOG" "$TRAZA"

# La salida de la trampa va a un archivo: la terminal queda limpia para la transcripción.
"$BIN" serve \
  --bind 127.0.0.1 \
  --ssh-port "$SSH_PORT" \
  --http-port "$HTTP_PORT" \
  --log "$LOG" > "$TRAZA" 2>&1 &
SERVIDOR_PID=$!
# Si el script se interrumpe, el servidor no queda huérfano.
trap 'kill "$SERVIDOR_PID" 2>/dev/null || true' EXIT INT TERM

# Espera a que la trampa anuncie que está escuchando (sin abrir una conexión de prueba).
for _ in $(seq 1 50); do
  if grep -q "Trampa SSH" "$TRAZA" 2>/dev/null; then
    break
  fi
  sleep 0.1
done

say "2. El atacante simulado entra y ejecuta órdenes"
"$BIN" attack --target "127.0.0.1:$SSH_PORT"

say "3. Lo que la trampa fue registrando en vivo"
cat "$TRAZA"

say "4. El registro en resumen"
"$BIN" show --log "$LOG"

say "5. El registro en crudo (JSONL)"
cat "$LOG"

kill "$SERVIDOR_PID" 2>/dev/null || true
wait "$SERVIDOR_PID" 2>/dev/null || true
trap - EXIT INT TERM

echo
echo "Registro completo en: $LOG"
say "Fin de la demo"
