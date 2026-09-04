#!/bin/sh
# W1-05 isolated container. The ONLY interesting thing in here is FLAG_W1-05.
# FLAG_W1_05 is always provided by docker-compose (own default there), so no
# shell default with braces is used (that would corrupt the value).
set -e
echo "$FLAG_W1_05" > /flag
chmod 644 /flag
mkdir -p /srv/exports
printf 'Danubius Bank - vypis uctu (ukazka)\n' > /srv/exports/vypis_2024.pdf
exec gunicorn -b 0.0.0.0:9005 -w 1 --threads 4 app:app
