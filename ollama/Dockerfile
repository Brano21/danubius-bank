FROM ollama/ollama:latest

# Pull the configured model on first start, then serve (see entrypoint.sh).
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
