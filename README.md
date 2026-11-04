# BP: Návrh a implementácia IDS v lokálnej sieti — zhrnutie projektu

Tento dokument zhŕňa, čo bolo postavené, ako to funguje a ako to spustiť. Slúži
ako referencia pri písaní bakalárskej práce (kapitoly 3–5). Mapovanie na
osnovu je v sekcii 10.

## 1. Architektúra (kap. 3.1, 3.2)

```
                    Hostiteľ (Ubuntu)
                    ┌──────────────────────────────────────────┐
                    │  Suricata 8.0.7 (systemd služba)           │
                    │  af-packet na rozhraní br-idsnet (pasívne) │
                    │  ET Open + vlastné pravidlá (local.rules)  │
                    │  → /var/log/suricata/eve.json              │
                    └───────────────┬──────────────────────────┘
                                    │
        ┌───────────────────────────┴──────────────────────────────┐
        │          Docker sieť "idsnet" (172.28.0.0/24), most br-idsnet │
        │                                                               │
        │  attacker 172.28.0.20   client 172.28.0.30                    │
        │  nmap, hping3, hydra,   benígna prevádzka na pozadí            │
        │  nikto, sqlmap          (web, DNS, SSH, FTP, ICMP)             │
        │                                                               │
        │  victim 172.28.0.10                 dvwa 172.28.0.11           │
        │  SSH, FTP (pasv 30000-30010),       DVWA (zraniteľná web app) │
        │  HTTP, DNS (dnsmasq, zóna .lab)                                │
        └───────────────────────────────────────────────────────────────┘

  EveBox 0.29.0 (Docker) — prehliadanie alertov, http://127.0.0.1:5636
```

**Umiestnenie senzora (3.2):** Suricata beží na hostiteľovi a pasívne číta
rozhranie mosta `br-idsnet`, cez ktorý ide všetka komunikácia medzi
kontajnermi. To zodpovedá nasadeniu NIDS na SPAN/mirror porte pred
chránenými servermi: senzor vidí celú prevádzku segmentu a nie je v ceste
(IDS, nie inline IPS).

**Izolácia:** porty kontajnerov sú publikované iba na `127.0.0.1`
hostiteľa (nie na LAN/WiFi). Útoky aj benígna prevádzka bežia vnútri `idsnet`.

**Prečo Docker namiesto plných VM:** pri zakladaní projektu bolo
k dispozícii ~27 GB voľného miesta. Kontajnery (kontajnerová virtualizácia)
sú rádovo ľahšie ako VM a zachovávajú sieťovú izoláciu (vlastný most,
samostatné sieťové menné priestory). Kompromis: zdieľané jadro (pozri 5.5).

**HOME_NET:** nastavený **len** na chránené servery `victim` a `dvwa`
(172.28.0.10, 172.28.0.11). Útočník aj klient spadajú pod `EXTERNAL_NET`
— presne ako v reálnom nasadení, kde používatelia aj útočníci prichádzajú
„zvonka“ na chránené servery. Veľa ET pravidiel je písaných pre smer
`EXTERNAL_NET → HOME_NET` a bez tohto nastavenia by nefungovali (sekcia 11).

## 2. Komponenty

| Komponent | Nástroj | Poznámka |
|---|---|---|
| IDS jadro | Suricata 8.0.7 | af-packet, systemd služba na hostiteľovi |
| Pravidlá | ET Open + vlastné | 52 828 ET pravidiel + 2 vlastné (profil *pred*) / 3 vlastné (profil *po*) |
| Ladenie FP | `threshold.config` | len v profile *po*, pozri sekciu 3 |
| Prehliadanie alertov | EveBox 0.29.0 | SQLite backend, nenáročné nasadenie; nemá plnohodnotné dashboardy (5.5) |
| Testovacia sieť | Docker Compose | victim, dvwa, attacker, client |
| Benígna prevádzka | `scripts/benign/benign_traffic.sh` | v kontajneri `client`, beží počas celého experimentu |
| Automatizácia (4.5) | `scripts/run_experiment.sh` | N behov × všetky scenáre + vyhodnotenie |
| Vyhodnotenie | `scripts/evaluate.py`, `scripts/aggregate.py` | TP/FP/FN/TN, precision, recall, F1, FPR, latencia, priemer ± SD |

## 3. Pravidlá a ich ladenie (kap. 3.4, 4.3, 5.3)

Dva profily vlastných pravidiel, prepínané skriptom `scripts/09_set_profile.sh before|after`:

| | Profil **pred** (`rules/local.rules`) | Profil **po** (`rules/tuned/`) |
|---|---|---|
| sid 9000001 | prístup zvonka na `/vulnerabilities/` (politika) | bez zmeny |
| sid 9000002 | ≥ 5 SYN / 5 s zo zdroja | ≥ **10** SYN / 5 s (rev 2) |
| sid 9000003 | — | SYN na **nepoužívané porty**, ≥ 10 / **120 s** (detekcia pomalého scanu) |
| `threshold.config` | prázdny | suppress `GPL ICMP PING *NIX` (2100366), `HTTP Response excessive header repetition` z DVWA (2221036), `ET INFO Web Crawl using Curl` (2002825) |

**Prečo tieto zmeny:** dáta zo starého behu (2026-09-23, prepočítané z
`eve.json`, `results/archive/2026-09-23/`) ukázali:
- 60 zo 66 FP alertov tvorili dve informačné signatúry (ping, hlavičky odpovedí DVWA),
- pravidlo 9000002 sa spustilo v **6 zo 7 okien**, ale aj 1× na benígnom FTP
  (pasívny režim = 2 spojenia na listing) a 1× pri prihlásení do DVWA.
  **Pôvodné tvrdenie, že sa spustilo „len na ssh_bruteforce“, bolo
  nesprávne** — vzniklo z top-3 súhrnu v `metrics.csv` (sekcia 11, bod 7),
- low-and-slow scan neprešiel žiadnym pravidlom.

**Pravidlo 9000003 — princíp:** chránené servery majú definované služby
(21, 22, 53, 80, pasívne FTP 30000–30010). SYN na iný port legitímny klient
neposiela, skener áno. Preto môže mať pravidlo dlhé okno a nízky prah
bez FP — a zachytí aj scan spomalený pod prah pravidla 9000002.
Limit: odstup > 12 s medzi paketmi prah 10/120 s opäť obíde (sekcia 9).

Postup ladenia pre prácu: beh *pred* → v `results/runs/before_*/signatures.csv`
pozri riadky `role=benign` → každú FP signatúru buď potlač (zdôvodni), alebo
ponechaj a prizná v práci → beh *po* → `results/comparison.md`.

**`threshold:type both` (nie `detection_filter`):** prvá verzia pravidla
9000002 s `detection_filter` vygenerovala 2,3 milióna alertov na jeden
20-sekundový SYN flood (alert na každý paket po dosiahnutí prahu).
`type both` = alert po dosiahnutí prahu a najviac 1× za okno.

## 4. Adresárová štruktúra

```
bp-ids/
├── compose/
│   ├── docker-compose.yml       # sieť idsnet + victim, dvwa, attacker, client, evebox
│   ├── victim/                  # SSH+FTP+HTTP+DNS so slabou konfiguráciou
│   └── attacker/Dockerfile      # nástroje útočníka (rovnaký image používa client)
├── rules/
│   ├── local.rules              # profil "pred ladením"
│   └── tuned/                   # profil "po ladení": local.rules + threshold.config
├── scripts/
│   ├── 00–08_*.sh               # pôvodné inštalačné/opravné skripty (história, sekcia 5)
│   ├── 09_set_profile.sh        # prepnutie profilu pravidiel before|after (sudo)
│   ├── 10_fix_log_rotation.sh   # logrotate pre eve.json (sudo)
│   ├── run_experiment.sh        # automatizácia: N behov + vyhodnotenie + agregácia
│   ├── evaluate.py              # vyhodnotenie jedného behu
│   ├── aggregate.py             # priemer ± SD cez behy, porovnanie pred/po
│   ├── benign/benign_traffic.sh # benígna prevádzka (kontajner client)
│   └── attacks/
│       ├── lib.sh               # ground truth: zápis časov, cieľa, nástroja, MITRE
│       ├── run_all.sh           # všetky scenáre za sebou (kontajner attacker)
│       ├── 00_baseline.sh       # čisté benígne okno 3 min (útočník nečinný)
│       ├── 01_portscan.sh … 05_web_scan_nikto.sh
│       ├── 06a_portscan_fast_control.sh   # kontrola k scenáru 6
│       ├── 06_portscan_slow.sh            # evázia: časové rozloženie
│       ├── 07_portscan_fragmented.sh      # evázia: fragmentácia
│       └── dvwa_setup.sh        # prihlásenie + reset DB v DVWA
├── results/
│   ├── runs/<profil>_r<N>_<čas>/   # attack_log.jsonl, meta.json, metrics.csv,
│   │                               # signatures.csv, summary.json
│   ├── aggregate_before.md, aggregate_after.md, comparison.md
│   └── archive/2026-09-23/         # historický beh (pôvodná metodika)
└── docs/                        # osnova, príprava na obhajobu
```

## 5. Setup (kap. 4.1, 4.2)

```bash
cd ~/Documents/bp-ids/scripts
./00_install_base.sh            # Docker, Suricata, nástroje
./01_install_attack_tools.sh
./02_fix_suricata.sh            # systemd-tmpfiles bug Ubuntu balíka
./03_configure_suricata.sh      # af-packet na br-idsnet, suricata-update (ET Open)
./04_grant_log_access.sh        # ACL na logy
./05_fix_homenet.sh             # HOME_NET = victim + dvwa (príp. 05b podľa indentácie)
./07_apply_fixes.sh             # local.rules do rule-files
./10_fix_log_rotation.sh        # NOVÉ: funkčná rotácia eve.json
./09_set_profile.sh before      # NOVÉ: profil pravidiel

cd ../compose && docker compose up -d --build
```

Poznámka: `06_install_gh_and_login.sh` je len nastavenie GitHubu,
`07b`/`08` sú opravné kroky z pôvodného ladenia a pri čistej inštalácii nie sú potrebné.

## 6. Spustenie experimentu (kap. 3.6, 4.5)

```bash
cd ~/Documents/bp-ids
./scripts/09_set_profile.sh before
./scripts/run_experiment.sh before 3     # ~3 × 9 min
./scripts/09_set_profile.sh after
./scripts/run_experiment.sh after 3
cat results/comparison.md                # tabuľka pred/po pre kap. 5.3
```

Jeden beh: `client` spustí benígnu prevádzku → `attacker` vykoná
`run_all.sh` (baseline 3 min, potom scenáre s 10 s pauzami) → benígna
prevádzka sa zastaví → `evaluate.py` → po všetkých behoch `aggregate.py`.
Medzi profilmi **nespúšťaj `suricata-update`** (zmenila by sa ET sada).

Alerty v dashboarde: http://127.0.0.1:5636

## 7. Testovacie scenáre (kap. 3.5)

| # | Scenár | Nástroj | MITRE ATT&CK | Typ |
|---|---|---|---|---|
| 0 | baseline_benign | client (web, DNS, SSH, FTP) | — | benígne okno (FP/TN) |
| 1 | portscan | nmap `-sS -T4 -p-` + `-sV -A` | TA0043/T1595, TA0007/T1046 | základný |
| 2 | dos_synflood | hping3 `--flood` 20 s | TA0040/T1498 (T1499.001) | základný |
| 3 | ssh_bruteforce | hydra | TA0006/T1110.001 | základný |
| 4 | web_sqli | sqlmap → DVWA | TA0001/T1190 | základný |
| 5 | web_scan_nikto | nikto → DVWA | TA0043/T1595.002 | základný |
| 6a | portscan_fast_control | nmap `-p 1-25` | TA0043/T1595 | základný (kontrola k 6) |
| 6 | portscan_low_and_slow | nmap `-p 1-25 --scan-delay 3s` | TA0043/T1595 | **evázny** |
| 7 | portscan_fragmented | nmap `-f -p 1-25` | TA0043/T1595 | **evázny** |

## 8. Metodika vyhodnotenia (kap. 3.6)

Podrobne v docstringu `scripts/evaluate.py`. V skratke:

- **Ground truth:** `attack_log.jsonl` (čas začiatku/konca, zdrojová a
  cieľová IP, nástroj, MITRE technika).
- **Priradenie alertov podľa IP:** IP útočníka v okne scenára = TP alert;
  IP klienta kedykoľvek = FP alert; útočník mimo okien = nepriradený.
- **Matica zámen na úrovni udalostí:** útočný scenár s ≥ 1 alertom = TP,
  bez alertu = FN; 10 s sloty čistého benígneho okna s alertom = FP,
  bez alertu = TN. Precision, recall, F1, FPR.
- **Evázne scenáre** sa vyhodnocujú zvlášť (nezapočítavajú sa do recall).
- **Doplnkovo:** latencia (prvý alert − začiatok), precision na úrovni
  alertov, FP alerty za minútu.
- **Opakovateľnosť:** 3 behy na profil, priemer ± smerodajná odchýlka.
- **Kritériá úspešnosti** (navrhnuté pre kap. 3.6):
  1. všetky základné scenáre detekované vo všetkých behoch (recall = 100 %),
  2. po ladení pokles FP alertov za minútu aspoň o 80 % pri zachovanom recall,
  3. evázne scenáre vyhodnotené zvlášť, s vysvetlením príčiny výsledku.

## 9. Výsledky (kap. 5)

### Nové behy

*Čakajú na spustenie* — po `run_experiment.sh` sa tabuľky vygenerujú do
`results/aggregate_*.md` a `results/comparison.md`. Čísla do práce preberaj
**len odtiaľ**, nikdy ručne z terminálu.

### Historický beh 2026-09-23 (pôvodná metodika, prepočítaný)

| Scenár | Detekované | Latencia (s) | Alertov | Prvý alert / najčastejšia signatúra |
|---|---|---|---|---|
| baseline (112 s, IP útočníka) | — | — | 66 FP | ping *NIX 30×, DVWA header repetition 30× |
| portscan | áno | 0,100 | 47 | NSE User-Agent 25×, sondy DB portov, 9000002 2× |
| low-and-slow (3 porty) | **nie** | — | 0 | — |
| dos_synflood | áno | 0,023 | 1728 | prvý: 9000002; STREAM anomálie 1712× |
| ssh_bruteforce | áno | 0,312 | 2 | 9000002, ET LibSSH BruteForce |
| web_sqli | áno | 0,155 | 142 | 9000001 89×, ET SQL Errors 18× |
| web_scan_nikto | áno | 0,124 | 759 | prvý: 9000002; ET XSS 267× |

Precision na úrovni alertov 97,6 %, ale na úrovni udalostí **11 z 12**
benígnych 10 s slotov malo alert (FPR 91,7 %, precision 31,2 %, F1 47,6 %),
~19 FP alertov/min. Vysoké alert-level percento bolo dané hlavne SYN
floodom (64 % všetkých TP alertov). Tento beh motivuje ladenie v kap. 5.3.

**Dôkaz úspešného útoku:** sqlmap pri SQLi reálne vydumpol tabuľku `users`
z DVWA vrátane hashov hesiel (`admin`, `gordonb`, `1337`, `pablo`, `smithy`)
a Suricata útok súčasne zachytila (vrátane vlastného pravidla 9000001).

### Obmedzenia, ktoré treba v práci pomenovať (5.5)

1. **Signatúrny/prahový prístup.** Jadrom je nasadenie a konfigurácia
   hotového IDS s prevažne hotovými pravidlami. Vlastný prínos: architektúra
   testbedu, HOME_NET/EXTERNAL_NET, 3 vlastné pravidlá, ladenie pred/po,
   evázne scenáre a metodika vyhodnotenia — nie vlastný detekčný algoritmus.
2. **Recall je binárny** (scenár áno/nie) — nehovorí, či alert zodpovedal
   správnemu typu útoku.
3. **Benígna prevádzka je syntetická** a krátka (minúty, nie dni).
4. **TN je definované cez časové sloty** — iná dĺžka slotu dá iné čísla.
5. **EveBox** slúži na prehliadanie a správu alertov, nemá plnohodnotné
   dashboardy; rozšírenie: ELK Stack alebo Wazuh dashboard.
6. **Kontajnery zdieľajú jadro** hostiteľa (slabšia izolácia ako VM).
7. **Low-and-slow s odstupom > 12 s** obíde aj pravidlo 9000003 — robustná
   detekcia vyžaduje behaviorálnu analýzu flow logov s dlhým oknom (SIEM).

## 10. Mapovanie na osnovu

| Osnova | Kde v projekte |
|---|---|
| 3.1 Topológia | sekcia 1, `compose/docker-compose.yml` |
| 3.2 Umiestnenie senzora | sekcia 1, `scripts/03_configure_suricata.sh` |
| 3.3 Logovanie, alerting, vizualizácia | EVE JSON, `10_fix_log_rotation.sh`, EveBox |
| 3.4 Pravidlá | sekcia 3, `rules/` |
| 3.5 Scenáre | sekcia 7, `scripts/attacks/` |
| 3.6 Metodika | sekcia 8, `scripts/evaluate.py` (docstring) |
| 4.1 Virtualizačné prostredie | sekcia 1, `compose/` |
| 4.2 Inštalácia a konfigurácia IDS | sekcia 5, `scripts/00–05` |
| 4.3 Pravidlá, evázia | sekcia 3, `rules/tuned/` |
| 4.4 EveBox | `compose/docker-compose.yml` (služba evebox) |
| 4.5 Automatizácia scenárov | `scripts/run_experiment.sh`, `run_all.sh`, `lib.sh` |
| 5.1–5.2 Výsledky a metriky | `results/runs/`, `results/aggregate_*.md` |
| 5.3 Ladenie pred/po | `results/comparison.md` |
| 5.4 Evázne scenáre | scenáre 6, 6a, 7 v `results/comparison.md` |
| 5.5 Diskusia a limity | sekcia 9 (obmedzenia), sekcia 11 |

## 11. Problémy, na ktoré sme narazili (diskusia/limity)

1. **Suricata Ubuntu balík** — `/var/run/suricata` na `tmpfs` bez
   `systemd-tmpfiles` pravidla. Riešenie: `/etc/tmpfiles.d/suricata.conf`.
2. **HOME_NET zahŕňal celú testovaciu sieť** (default `172.16.0.0/12`),
   pravidlá `EXTERNAL_NET → HOME_NET` sa nespúšťali. Riešenie: HOME_NET len
   na chránené servery.
3. **sqlmap v `--batch`** akceptoval neprihlásenú session pri presmerovaní
   na login. Riešenie: `--drop-set-cookie`. Cachovanie techniky medzi behmi:
   `--flush-session`.
4. **`eve.json` bez rotácie** — narástol na 4,3 GB, po „oprave“
   `rotate-interval: day` opäť na 1,47 GB. Ten parameter rotuje len pri
   súbore s časovým vzorom v mene; pri statickom `eve.json` nerobí nič.
   Riešenie: `logrotate` + SIGHUP (`10_fix_log_rotation.sh`).
5. **`detection_filter` → 2,3 milióna alertov** na jeden SYN flood.
   Riešenie: `threshold:type both`.
6. **Nekonzistentné čísla README vs. `metrics.csv`** — ručné prepisovanie
   z terminálu. Poučenie: čísla len z vygenerovaných súborov.
7. **Záver z orezaného súhrnu** — `metrics.csv` ukazoval len top-3
   signatúry, z čoho vznikol nesprávny záver o pravidle 9000002. Riešenie:
   `signatures.csv` s úplným rozpisom.
8. **Low-and-slow skenoval len 3 porty** — pod prahom pravidla aj bez
   spomalenia, evázia nebola preukázaná. Riešenie: 25 portov + kontrolný
   scenár 6a.
9. **Benígna prevádzka z IP útočníka** — FP sa nedali odlíšiť počas útokov.
   Riešenie: samostatný kontajner `client`.
10. **Porty publikované na 0.0.0.0** (SSH so slabým heslom, EveBox bez
    autentifikácie dostupné z LAN). Riešenie: väzba na 127.0.0.1.

## 12. Návrhy na rozšírenie

- Behaviorálna detekcia pomalých scanov nad flow logmi (Ring et al., 2018)
- Pokročilejšia evázia: prekrývajúce sa fragmenty, TTL triky (Ptacek & Newsham)
- Porovnanie Suricata vs. Snort 3 / Zeek na rovnakých scenároch
- ELK Stack alebo Wazuh dashboard namiesto EveBox
- FTP brute-force scenár, dlhšia/realistickejšia benígna prevádzka
