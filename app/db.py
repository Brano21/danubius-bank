"""Thin PostgreSQL access layer.

NOTE: vulnerable modules deliberately build SQL by string concatenation to
create real (not simulated) SQL-injection. This helper only manages the
connection; it does not force parameterization.
"""
import psycopg2
import psycopg2.extras
from flask import current_app, g


def get_db():
    if "db" not in g:
        c = current_app.config
        g.db = psycopg2.connect(
            host=c["DB_HOST"], port=c["DB_PORT"], dbname=c["DB_NAME"],
            user=c["DB_USER"], password=c["DB_PASSWORD"],
        )
        g.db.autocommit = True
    return g.db


def close_db(_e=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def fetch_all(sql, params=None):
    cur = get_db().cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute(sql, params)
    rows = cur.fetchall()
    cur.close()
    return rows


def fetch_one(sql, params=None):
    cur = get_db().cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute(sql, params)
    row = cur.fetchone()
    cur.close()
    return row
