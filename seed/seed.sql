-- Danubius Bank - schema + base seed.
-- Runs via postgres docker-entrypoint-initdb.d on a FRESH volume, so
-- `docker compose down -v && up` restores a clean vulnerable state.
--
-- Flags are NOT stored here. The one seed-time exception (W1-02, the masked
-- VIP card number) will be injected by a separate init script at Week 1; the
-- VIP card row below marks where it goes.

DROP TABLE IF EXISTS transactions;
DROP TABLE IF EXISTS cards;
DROP TABLE IF EXISTS accounts;
DROP TABLE IF EXISTS clients;

CREATE TABLE clients (
    id          SERIAL PRIMARY KEY,
    username    TEXT NOT NULL UNIQUE,
    password    TEXT NOT NULL,           -- plaintext on purpose (training target)
    full_name   TEXT NOT NULL,
    role        TEXT NOT NULL DEFAULT 'client',
    is_vip      BOOLEAN NOT NULL DEFAULT FALSE,
    created_at  TIMESTAMP NOT NULL DEFAULT now()
);

CREATE TABLE accounts (
    id            SERIAL PRIMARY KEY,
    client_id     INTEGER NOT NULL REFERENCES clients(id),
    iban          TEXT NOT NULL,
    balance       NUMERIC(14,2) NOT NULL DEFAULT 0,
    currency      TEXT NOT NULL DEFAULT 'EUR',
    account_limit NUMERIC(14,2) NOT NULL DEFAULT 5000
);

CREATE TABLE cards (
    id           SERIAL PRIMARY KEY,
    account_id   INTEGER NOT NULL REFERENCES accounts(id),
    card_number  TEXT NOT NULL,          -- full PAN (target of W1-02 UNION leak)
    card_holder  TEXT NOT NULL,
    expiry       TEXT NOT NULL,
    cvv          TEXT NOT NULL,
    status       TEXT NOT NULL DEFAULT 'active',
    card_type    TEXT NOT NULL DEFAULT 'Visa Debit',
    is_vip       BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE TABLE transactions (
    id            SERIAL PRIMARY KEY,
    account_id    INTEGER NOT NULL REFERENCES accounts(id),
    ts            TIMESTAMP NOT NULL DEFAULT now(),
    amount        NUMERIC(14,2) NOT NULL,
    currency      TEXT NOT NULL DEFAULT 'EUR',
    counterparty  TEXT NOT NULL,
    note          TEXT DEFAULT '',       -- stored-XSS sink for W1-03
    direction     TEXT NOT NULL DEFAULT 'out'
);

-- Clients (id 1 = first client; W1-01 login bypass lands here) --------------
INSERT INTO clients (username, password, full_name, role, is_vip) VALUES
  ('j.novak',  'jesenina12',   'Jan Novak',        'client', FALSE),
  ('m.horvat', 'leto2023!',    'Maria Horvathova', 'client', FALSE),
  ('p.kovac',  'Qwerty!42',    'Peter Kovac',      'client', TRUE),
  ('admin',    'S3cr3t-Adm1n', 'Danubius Admin',   'admin',  FALSE),
  ('e.tomas',  'macka.mnau',   'Eva Tomasova',     'client', FALSE);

INSERT INTO accounts (client_id, iban, balance, currency, account_limit) VALUES
  (1, 'SK8975000000000012345671',   1240.55, 'EUR',  5000),
  (2, 'SK8975000000000012345672',   8300.10, 'EUR',  5000),
  (3, 'SK8975000000000012345673', 154200.00, 'EUR', 50000),   -- VIP
  (4, 'SK8975000000000012345674',     50.00, 'EUR', 999999),
  (5, 'SK8975000000000012345675',   2015.75, 'EUR',  5000);

-- Realistic customer cards. Storing the PAN + CVV in plaintext is itself the
-- kind of bad practice that makes the W1-02 leak so damaging. Card id 3 is the
-- VIP card whose number is replaced by FLAG_W1-02 at seed time (see
-- 20-inject-w1-02-flag.sh). Card id 4 is a customer's old, blocked card
-- (W2-02 target); the staff "admin" account has no payment card.
INSERT INTO cards (account_id, card_number, card_holder, expiry, cvv, status, card_type, is_vip) VALUES
  (1, '4917556120438811', 'JAN NOVAK',        '08/27', '221', 'active',  'Visa Debit',       FALSE),
  (2, '5355982144770290', 'MARIA HORVATHOVA', '03/26', '804', 'active',  'Mastercard Debit', FALSE),
  (3, '4917450012006710', 'PETER KOVAC',      '11/28', '311', 'active',  'Visa Gold',        TRUE),
  (1, '4917556120431179', 'JAN NOVAK',        '01/25', '742', 'blocked', 'Visa Debit',       FALSE),
  (5, '5355982144770520', 'EVA TOMASOVA',     '07/26', '145', 'active',  'Mastercard Debit', FALSE);

INSERT INTO transactions (account_id, amount, currency, counterparty, note, direction) VALUES
  (1,   -45.90, 'EUR', 'Tesco Stores SR',   'groceries',    'out'),
  (1,  -120.00, 'EUR', 'SPP a.s.',          'gas invoice',  'out'),
  (1,  1500.00, 'EUR', 'Employer Ltd.',     'salary',       'in'),
  (2,   -12.49, 'EUR', 'Netflix',           'subscription', 'out'),
  (2,  -890.00, 'EUR', 'Furniture Plus',    'sofa',         'out'),
  (3, -9800.00, 'EUR', 'Auto Impex',        'car deposit',  'out'),
  (3, 25000.00, 'EUR', 'Investment Acct.',  'dividend',     'in'),
  (5,   -30.00, 'EUR', 'Danube Cafe',       'coffee & cake','out');
