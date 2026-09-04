#!/bin/sh
set -e
# Start the Ollama server, wait for it, pull the model, then keep serving.
ollama serve &
srv=$!
echo "[ollama-init] waiting for server..."
until ollama list >/dev/null 2>&1; do sleep 1; done
echo "[ollama-init] pulling ${OLLAMA_MODEL:-llama3.2:3b} (first run downloads ~2GB)..."
ollama pull "${OLLAMA_MODEL:-llama3.2:3b}" || echo "[ollama-init] pull failed; serving anyway"
echo "[ollama-init] model ready."
wait $srv
