# Historicky beh 2026-09-23 (povodna metodika)

- `attack_log.jsonl`, `metrics.csv` - povodne subory z behu (stary evaluate.py, top-3 signatury).
- `*_recomputed.*`, `signatures_full.csv` - ten isty beh prepocitany novym
  `scripts/evaluate.py` z eve.json (dna 2026-11-04). Uplny rozpis signatur ukazuje,
  ze pravidlo sid 9000002 sa spustilo v 6 zo 7 okien vratane baseline
  (povodny zaver "len na ssh_bruteforce" vznikol z orezania na top-3).

Obmedzenia tohto behu (preto bol nahradeny novou metodikou):
benigna prevadzka isla z IP utocnika, iba 1 beh, baseline 112 s,
low-and-slow skenoval len 3 porty (pod prahom pravidla aj bez spomalenia).
