# Full python:3.12 (NOT slim) on purpose: it ships bash, cat, ls, id, coreutils
# so the W1-05 injection payloads actually work (acceptance condition).
FROM python:3.12

ENV PYTHONUNBUFFERED=1
WORKDIR /srv

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py entrypoint.sh ./
RUN chmod +x entrypoint.sh

EXPOSE 9005
ENTRYPOINT ["./entrypoint.sh"]
