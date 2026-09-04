# Referenčné opravy

Hlavná vetva `master` je plne zraniteľná. Ku každej zraniteľnosti existuje vetva
`fix/<id>` s **jediným** commitom — diff medzi `master` a `fix/<id>` JE referenčná
oprava. Vetva `fixes` obsahuje všetky opravy naraz.

Oprava sa dá zobraziť takto:

```bash
git diff master..fix/W1-01           # jedna oprava
git log --oneline fix/W2-03        # commit opravy
git diff master..fixes -- app/       # všetky opravy naraz
```

Každá oprava je **overená** regresným balíkom: na `fix/<id>` daný test v
`tests/run_tests.py` prejde z PASS na FAIL (zraniteľnosť je zavretá), ostatné
ostanú PASS. Na `master` prechádzajú všetky.

| ID | Vetva | Podstata opravy | Stav |
|----|-------|-----------------|------|
| W1-01 | `fix/W1-01` | parametrizovaný login dotaz | ✅ |
| W1-02 | `fix/W1-02` | parametrizované vyhľadávanie | ✅ |
| W1-03 | `fix/W1-03` | escapovaný výstup poznámky | ✅ |
| W1-04 | `fix/W1-04` | escapovaný odraz `q` | ✅ |
| W1-05 | `fix/W1-05` | `subprocess` bez shellu (argv) | ✅ |
| W2-01 | `fix/W2-01` | kontrola vlastníctva objektu | ✅ |
| W2-02 | `fix/W2-02` | kontrola admin roly | ✅ |
| W2-03 | `fix/W2-03` | allowlist polí (mass assignment) | ✅ |
| W2-04 | `fix/W2-04` | limit pre každú menu | ✅ |
| W2-05 | `fix/W2-05` | generická chyba (bez úniku) | ✅ |
| W3-01 | `fix/W3-01` | tajomstvo mimo system promptu | ✅ |
| W3-02 | `fix/W3-02` | chránená hodnota mimo LLM kontextu | ✅ |
| W3-03 | `fix/W3-03` | tajomstvo mimo kontextu (filter = defense in depth) | ✅ |
| W3-04 | `fix/W3-04` | nástroj obmedzený na volajúceho (least privilege) | ✅ |
| — | `fixes` | všetky opravy naraz | ✅ |

Detailné vysvetlenie a otázky: `secure-coding/week1.md`, `week2.md`, `week3.md`.
