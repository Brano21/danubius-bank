# Patch súbory referenčných opráv

Každý `.patch` je diff medzi zraniteľným `master` a opravou danej úlohy
(pôvodne vetva `fix/<id>`). Obsahujú **len samotnú opravu**.

```bash
cat W1-01.patch                     # pozri opravu
git apply --check W1-01.patch       # over aplikovateľnosť (bez zmeny)
git apply W1-01.patch               # aplikuj na master
git checkout -- .                   # vráť späť
git apply ALL.patch                 # všetky opravy naraz
```

Vysvetlenie „prečo je oprava správna a čo by nesprávna prehliadla" je v
`secure-coding/week1.md`, `week2.md`, `week3.md`.
