FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
WORKDIR /srv

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ ./app/
COPY wsgi.py .

EXPOSE 8080
# Single worker + threads: keeps the in-memory W1-03 capture store consistent
# across requests (and keeps FLAG_W1-03 out of the DB / out of SQLi reach).
CMD ["gunicorn", "-b", "0.0.0.0:8080", "-w", "1", "--threads", "16", "--worker-class", "gthread", "--access-logfile", "-", "wsgi:app"]
