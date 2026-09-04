"""Minimal Ollama chat client (blocking, non-streaming)."""
import json

import requests
from flask import current_app


def _url(path):
    return current_app.config["OLLAMA_URL"] + path


def _model():
    return current_app.config["OLLAMA_MODEL"]


def chat(system, user, timeout=120):
    payload = {
        "model": _model(),
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
        "stream": False,
        "options": {"temperature": 0.6},
    }
    try:
        r = requests.post(_url("/api/chat"), json=payload, timeout=timeout)
        r.raise_for_status()
        return r.json()["message"]["content"]
    except Exception as e:  # noqa: BLE001
        return "[asistent momentalne nedostupny: " + str(e) + "]"


def chat_with_tools(system, user, tools, handlers, timeout=120):
    """One-step tool use: ask the model; if it calls a tool, run it and surface
    the raw tool result (so the outcome is visible regardless of the model's
    final phrasing)."""
    payload = {
        "model": _model(),
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
        "tools": tools,
        "stream": False,
    }
    try:
        r = requests.post(_url("/api/chat"), json=payload, timeout=timeout)
        r.raise_for_status()
        message = r.json()["message"]
    except Exception as e:  # noqa: BLE001
        return "[asistent momentalne nedostupny: " + str(e) + "]"

    calls = message.get("tool_calls") or []
    if not calls:
        return message.get("content", "")

    lines = []
    for c in calls:
        fn = c.get("function", {}).get("name")
        args = c.get("function", {}).get("arguments", {}) or {}
        if isinstance(args, str):
            try:
                args = json.loads(args)
            except ValueError:
                args = {}
        if fn in handlers:
            result = handlers[fn](**args) if isinstance(args, dict) else handlers[fn](args)
            lines.append(
                "Nastroj " + fn + "(" + json.dumps(args, ensure_ascii=False)
                + ") -> " + json.dumps(result, ensure_ascii=False)
            )
    return "\n".join(lines) if lines else message.get("content", "")
