#!/bin/sh
# W1-02 seed exception (brief req #5): the ONE flag that must live in the DB,
# because the task is to LEAK it via UNION-based SQLi. It is stored as the VIP
# card's "masked" number. No other flag is ever placed in the database.
# FLAG_W1_02 is always provided by docker-compose (it has its own default there),
# so no shell default is used here - a shell default with braces would corrupt
# the value by appending a stray '}'.
set -e
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
  -c "UPDATE cards SET card_number = '$FLAG_W1_02' WHERE is_vip = TRUE;"
