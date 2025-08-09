#!/bin/bash

set -e

# --- argument & range check (must be 1..3) ---
if [ -z "$1" ] || ! [[ "$1" =~ ^[0-9]+$ ]] || [ "$1" -lt 1 ] || [ "$1" -gt 3 ]; then
  echo "./launcher.sh <number of decrypters> number between 1-3"
  exit 1
fi
NUM="$1"
# --------------------------------------------------

SHARED_DIR="./mta_shared_dir"
LOG_DIR="/var/log"

# Make sure shared dir exists
mkdir -p "$SHARED_DIR"

echo "[*] Cleaning logs and pipes..."
rm -f "$SHARED_DIR/encrypter_pipe"
rm -f "$SHARED_DIR/decrypter_pipe_"*

if [ ! -f "$SHARED_DIR/config.txt" ]; then
  echo "16" > "$SHARED_DIR/config.txt"
  echo "[+] Created default config.txt (password length = 16)"
fi

echo "[*] Building Docker images..."
docker build -t encrypter-image ./encrypter
docker build -t decrypter-image ./decrypter

echo "[*] Running Encrypter..."
docker rm -f encrypter || true
docker run -d \
  --name encrypter \
  -v "$(pwd)/mta_shared_dir:/mnt/mta" \
  encrypter-image

echo "[*] Running $NUM Decrypters..."
for i in $(seq 1 "$NUM"); do
  docker rm -f "decrypter_$i" || true
  docker run -d \
    --name "decrypter_$i" \
    -v "$(pwd)/mta_shared_dir:/mnt/mta" \
    decrypter-image
done

echo "[✓] All containers are up and running."
