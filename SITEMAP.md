# Site mapa — Danubius Bank CTF

Orientácia: čo kde je, čo je **reálna funkcia**, čo **terč úlohy**, čo **nástroj
útočníka**, a aká autentifikácia treba.

## Vrstvy / služby (docker-compose)

```
prehliadač
   │  :8080 (jediné publikované)
   ▼
[ gate ]  ── prihlásenie hráča + logovanie + admin dashboard (mimo zraniteľnej appky)
   │  interná sieť (proxy)
   ▼
[ web ]  ── Flask "Danubius Bank" (zraniteľná appka)
   ├── [ db ]        PostgreSQL (interná)
   ├── [ ollama ]    LLM model pre Danubku (interná, W3)
   └── [ exporter ]  izolovaný kontajner pre W1-05 (internal sieť, cap_drop:ALL)
```

## 1) Brána — `/_gate/*` (bezpečnostná vrstva, NIE terč)

| Cesta | Čo to je | Auth |
|-------|----------|------|
| `/_gate/login` | Prihlásenie hráča (jediné silné prihlásenie pred Danubiusom; 7-dňový token) | verejné |
| `/_gate/logout` | Odhlásenie (netreba používať) | hráč |
| `/_gate/admin/login` | Prihlásenie operátora | verejné |
| `/_gate/admin` | **Live dashboard** — aktivita hráčov (monitoring) | admin |

> Bez gate prihlásenia je **všetko** nižšie neprístupné (redirect na `/_gate/login`).

## 2) Danubius web — verejná časť (po bráne, pred bankovým loginom)

| Cesta | Čo to je | Úloha |
|-------|----------|-------|
| `/` | Landing (marketing) / po bank-logine portál-domov | — |
| `/login` | **Bankový login** | **terč W1-01** (SQLi bypass) |
| `/register` | **Registrácia** (email + 2× heslo, bez overenia mailu; účet sa uloží) | reálna funkcia (surface na testovanie) |
| `/collector` | Pomôcka: zadaj token → tvoj collector | nástroj útočníka (W1-03) |
| `/w1-03/collect/<token>` | Collector útočníka (zachytené dáta) | nástroj útočníka (W1-03) |

## 3) Danubius web — portál (po bankovom logine)

| Cesta | Čo to je | Úloha |
|-------|----------|-------|
| `/dashboard` | Prehľad účtu | **flag W1-01** sa tu zobrazí (klient id 1) |
| `/transactions` | Vyhľadávanie v transakciách | **terč W1-02** (UNION SQLi) |
| `/search` | Vyhľadávanie na stránke (za loginom) | **terč W1-04** (Reflected XSS) |
| `/search/solved` | Mechanika W1-04 — vyžaduje nonce zo stránky (holý GET nedá flag) | (W1-04) |
| `/transfer` | Nový prevod (pole *Poznámka*) | **terč W1-03** (Stored XSS) |
| `/w1-03/report/<id>` | „Nahlásiť adminovi" → emulovaný admin | mechanika W1-03 |
| `/admin/review` | Admin kontrola prevodov (render poznámky **bez escapovania**) | **sink W1-03**; len rola `admin` |
| `/export` | Export výpisu do PDF (proxy na exporter) | **terč W1-05** (OS injection) |
| `/logout` | Odhlásenie z banky | — |

## 4) REST API — `/api/v1/*` (WEEK ≥ 2, token auth)

| Cesta | Metóda | Úloha |
|-------|--------|-------|
| `/api/v1/login` | POST | vydá token (rovnaká injekcia ako W1-01) |
| `/api/v1/me` | GET | info o tokene |
| `/api/v1/accounts/{id}/transactions` | GET | **W2-01 BOLA** |
| `/api/v1/admin/cards/{id}/unblock` | POST | **W2-02 BFLA** |
| `/api/v1/profile` | PATCH | **W2-03 mass assignment** |
| `/api/v1/admin/portal` | GET | overí rolu → flag (W2-03) |
| `/api/v1/transfers` | POST | **W2-04 fraud bypass** (mena) |
| `/api/v1/statements` | GET | **W2-05 error leak** (nenumerický `account`) |

## 5) Asistent Danubka — `/assistant/*` (WEEK ≥ 3, za bránou)

| Cesta | Čo to je | Úloha |
|-------|----------|-------|
| `/assistant/` | Chat s Danubkou | **W3-01** priama injekcia |
| `/assistant/secure` | „Bezpečný režim" (chránený údaj) | **W3-02** obídenie mlčania |
| `/assistant/summarize` | Zhrnutie dokumentu | **W3-03** nepriama injekcia |
| `/assistant/agent` | Agent s nástrojom `get_balance` | **W3-04** excessive agency |

## Odomykanie po týždňoch (`WEEK`)
- `WEEK=1` → časti 2 a 3 (web, W1)
- `WEEK=2` → + API (4, W2)
- `WEEK=3` → + Danubka (5, W3)
Uzamknutý týždeň **nie je zaregistrovaný** — jeho cesty neexistujú.

## Legenda
- **terč úlohy** = zámerne zraniteľné miesto (rieši sa v CTF)
- **nástroj útočníka** = pomôcka na exploit (nie funkcia banky) — napr. collector
- **reálna bezpečnosť** = len brána (`/_gate/*`); bankový `/login` je terč, nie ochrana
