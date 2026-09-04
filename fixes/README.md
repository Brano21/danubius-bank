# Referenčné opravy

Repo drží len vetvu **`master`** (zámerne zraniteľný terč). Referenčné opravy sú
uložené ako **patch súbory** v [`fixes/patches/`](patches/) a podrobne vysvetlené
v `secure-coding/week1.md`, `week2.md`, `week3.md`.

Zobraziť / aplikovať opravu:

```bash
cat fixes/patches/W1-01.patch                 # pozri opravu
git apply --check fixes/patches/W1-01.patch   # over, že sa dá aplikovať
git apply fixes/patches/W1-01.patch           # aplikuj na master (zavrie danú vuln)
git checkout -- .                             # vráť späť (master ostáva zraniteľný)
git apply fixes/patches/ALL.patch             # všetky opravy naraz
```

Každá oprava je **overená** regresným balíkom: po aplikovaní `fix` daný test v
`tests/run_tests.py` prejde z PASS na FAIL (zraniteľnosť je zavretá), ostatné
ostanú PASS. Na čistom `master` prechádzajú všetky.

| ID | Patch | Podstata opravy |
|----|-------|-----------------|
| W1-01 | `patches/W1-01.patch` | parametrizovaný login dotaz |
| W1-02 | `patches/W1-02.patch` | parametrizované vyhľadávanie |
| W1-03 | `patches/W1-03.patch` | escapovaný výstup poznámky |
| W1-04 | `patches/W1-04.patch` | escapovaný odraz `q` |
| W1-05 | `patches/W1-05.patch` | `subprocess` bez shellu (argv) |
| W2-01 | `patches/W2-01.patch` | kontrola vlastníctva objektu |
| W2-02 | `patches/W2-02.patch` | kontrola admin roly |
| W2-03 | `patches/W2-03.patch` | allowlist polí (mass assignment) |
| W2-04 | `patches/W2-04.patch` | limit pre každú menu |
| W2-05 | `patches/W2-05.patch` | generická chyba (bez úniku) |
| W3-01 | `patches/W3-01.patch` | tajomstvo mimo system promptu |
| W3-02 | `patches/W3-02.patch` | chránená hodnota mimo LLM kontextu |
| W3-03 | `patches/W3-03.patch` | tajomstvo mimo kontextu (filter = defense in depth) |
| W3-04 | `patches/W3-04.patch` | nástroj obmedzený na volajúceho (least privilege) |
| — | `patches/ALL.patch` | všetky opravy naraz |
