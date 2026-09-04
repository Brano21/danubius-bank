"""Week 3 - Danubka LLM assistant. Locked until WEEK>=3.

Maps to OWASP Top 10 for LLM Apps: LLM01 Prompt Injection, LLM02 Sensitive
Information Disclosure, LLM06 Excessive Agency. Backend calls a local Ollama
model (see ollama service in docker-compose). Each vuln is in its own file.
"""
from flask import Blueprint

bp = Blueprint("week3", __name__, url_prefix="/assistant")

from . import (  # noqa: E402,F401
    w3_01_direct,
    w3_02_secrecy,
    w3_03_indirect,
    w3_04_agency,
)
