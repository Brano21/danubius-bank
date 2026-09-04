# Secure coding — Týždeň 4 (detekčná fáza)

Týždeň 4 nemá klasickú opravu. Namiesto nej hráč navrhne, aké logovanie a
alerty by útok zachytili skôr (mapuje sa na A09 Logging & Alerting Failures).

- **W4-01** — Nájdi vstupný bod (log analýza)
- **W4-02** — Zrekonštruuj rozsah úniku
- **W4-03** — Časová os lateral movementu
- **W4-04** — Statická analýza (benígnej) vzorky
- **W4-05** — Malware analysis report (human-graded, mimo appky)

Referenčná odpoveď: čo appka nelogovala a mala (chýbajúce audit logy pri
zmene role, pri prístupe k cudzím objektom, pri opakovaných zlyhaniach loginu;
absencia alertu na anomálny počet requestov / UNION vzory v parametroch).
