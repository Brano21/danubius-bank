import os


class Config:
    """Central config. Week modules unlock cumulatively via WEEK (1..4).

    Flags are NEVER hardcoded and NEVER stored in the database (one seed-time
    exception, W1-02). They live only in the container environment and are
    emitted by application logic after a task's condition is met. See flags.py.
    """

    WEEK = int(os.environ.get("WEEK", "1"))
    SECRET_KEY = os.environ.get("SECRET_KEY", "dev-danubius-not-secret")

    DB_HOST = os.environ.get("DB_HOST", "db")
    DB_PORT = int(os.environ.get("DB_PORT", "5432"))
    DB_NAME = os.environ.get("DB_NAME", "danubius")
    DB_USER = os.environ.get("DB_USER", "danubius")
    DB_PASSWORD = os.environ.get("DB_PASSWORD", "danubius")

    # W1-05 OS-command-injection exporter runs in its OWN isolated container.
    # The main web app only proxies the filename to it. (Wired at Week 1.)
    EXPORTER_URL = os.environ.get("EXPORTER_URL", "http://exporter:9005")

    # Week 3 LLM assistant (Ollama). Wired at Week 3.
    OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://ollama:11434")
    OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "llama3.2:3b")
