# Regresné testy (W1–W3)

Overujú, že zraniteľnosti **stále fungujú** (flag je stále dosiahnuteľný cez daný
exploit). Spusti po každej zmene, aby si zachytil, že si niečo nepokazil.

Testy idú **cez bránu** (ako reálny hráč), takže zároveň overujú, že brána
exploity nerozbila.

## Spustenie
```bash
# appka musí bežať (docker compose up); ideálne WEEK=3, nech sú W2/W3 odomknuté
python tests/run_tests.py             # W1 (+ W2/W3 ak sú odomknuté)
python tests/run_tests.py --with-llm  # aj W3 (pomalé, LLM je nedeterministický)
```

- **W1/W2** sú deterministické a rozhodujú o exit kóde (`0` = OK, `1` = zlyhanie).
- **W3** je best-effort (LLM) — reportuje sa, retry-uje, ale nezhodí suite.

Žiadne závislosti — čistá štandardná knižnica Pythonu 3.

## Konfigurácia (env premenné)
- `BASE_URL` (default `http://localhost:8080`)
- `GATE_USER` / `GATE_PASS` (default `tester` / `test123` z `gate/players.json`)

## Použitie pri opravách
Po aplikovaní opravy na vetve `fix/<id>` sa príslušný test má **zmeniť na FAIL**
(oprava zavrie zraniteľnosť) — to je očakávané a potvrdzuje, že oprava účinkuje.
Na vetve `main` musia prejsť všetky (deterministické).
