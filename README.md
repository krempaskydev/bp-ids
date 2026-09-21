# BP: Návrh a implementácia IDS v lokálnej sieti — zhrnutie projektu

Tento dokument zhŕňa, čo bolo postavené, ako to funguje a ako to spustiť. Slúži
ako referencia pri písaní samotnej bakalárskej práce (kapitoly 3–5).

## 1. Architektúra

```
                    Hostiteľ (Ubuntu, tvoje PC)
                    ┌─────────────────────────────────────┐
                    │  Suricata (systemd služba)            │
                    │  sleduje rozhranie br-idsnet           │
                    │  → /var/log/suricata/eve.json          │
                    └───────────────┬─────────────────────┘
                                    │ (af-packet, pasívne sledovanie)
        ┌───────────────────────────┴───────────────────────────┐
        │              Docker sieť "idsnet" (172.28.0.0/24)       │
        │                     most br-idsnet                      │
        │                                                          │
        │   attacker            victim              dvwa            │
        │   172.28.0.20         172.28.0.10          172.28.0.11     │
        │   nmap, hping3,       SSH, FTP, HTTP        DVWA (web app  │
        │   hydra, nikto,       (zámerne slabé        so zraniteľ-  │
        │   sqlmap              heslá pre testy)      nosťami)      │
        └──────────────────────────────────────────────────────────┘

  EveBox (Docker kontajner) — dashboard na porte 5636, číta eve.json
```

**Prečo Docker namiesto VirtualBox/GNS3:** pri zakladaní projektu si mal len
~27 GB voľného miesta, Docker kontajnery sú rádovo ľahšie ako plné VM a
zachovávajú si sieťovú izoláciu potrebnú pre realistický test.

**Dôležitý architektonický detail (dobrý bod do kap. 3):** `HOME_NET` v
Suricate je nastavený **len** na `victim` a `dvwa` (172.28.0.10,
172.28.0.11). Útočník (172.28.0.20) tak spadá pod `EXTERNAL_NET` — presne ako
v reálnom nasadení, kde útočník prichádza "zvonka" na chránené servery.
Veľa ET-open pravidiel je písaných práve pre smer `EXTERNAL_NET → HOME_NET` a
bez tohto nastavenia by vôbec nefungovali (mali sme to ako reálny bug počas
implementácie, pozri sekciu 6).

## 2. Komponenty

| Komponent | Nástroj | Poznámka |
|---|---|---|
| IDS jadro | Suricata 8.0.7 | af-packet mód, beží ako systemd služba priamo na hostiteľovi |
| Pravidlá | Emerging Threats Open (ET-open) | 52 828 pravidiel, aktualizuje sa cez `suricata-update` |
| Dashboard | EveBox 0.29.0 | Docker kontajner, SQLite backend (bez ťažkého ELK), http://localhost:5636 |
| Testovacia sieť | Docker Compose | 3 kontajnery: victim, dvwa, attacker |
| Cieľ útokov | victim (vlastný Ubuntu image) | SSH (slabé heslo testuser/testpass123), FTP (anonymous), Apache |
| Cieľ webových útokov | dvwa (`vulnerables/web-dvwa`) | DVWA v1.10, security level "low" |
| Útočné nástroje | nmap, hping3, hydra, nikto, sqlmap | v attacker kontajneri, izolované od hostiteľa |
| Vyhodnotenie | `scripts/evaluate.py` | počíta TP/FP/FN, precision, recall, latenciu |

## 3. Adresárová štruktúra

```
bp-ids/
├── compose/
│   ├── docker-compose.yml      # definícia siete a kontajnerov
│   ├── victim/Dockerfile       # SSH+FTP+HTTP server so slabými heslami
│   └── attacker/Dockerfile     # nmap, hping3, hydra, nikto, sqlmap
├── scripts/
│   ├── 00-05_*.sh               # jednorazové inštalačné/opravné skripty (host)
│   ├── attacks/
│   │   ├── lib.sh                # spoločné logovanie časov útokov
│   │   ├── 00_baseline.sh        # benígna prevádzka (meranie FP)
│   │   ├── 01_portscan.sh        # nmap SYN scan + service/OS detekcia
│   │   ├── 02_dos_synflood.sh    # hping3 SYN flood (20s)
│   │   ├── 03_ssh_bruteforce.sh  # hydra brute-force na SSH
│   │   ├── 04_web_sqli.sh        # sqlmap SQL injection na DVWA
│   │   ├── 05_web_scan_nikto.sh  # nikto sken zraniteľností
│   │   ├── dvwa_setup.sh         # pomocný: prihlásenie + reset DB v DVWA
│   │   └── run_all.sh            # spustí všetky scenáre za sebou
│   └── evaluate.py              # vyhodnotenie: TP/FP/FN, precision, recall, latencia
├── results/
│   ├── attack_log.jsonl         # "ground truth" - presné časy každého útoku
│   └── metrics.csv              # výstup evaluate.py
└── rules/, docs/                # voľné priečinky pre tvoje poznámky/screenshoty
```

## 4. Ako to spustiť odznova (setup)

Toto je už väčšinou hotové na tvojom stroji, ale pre kapitolu 4 (Implementácia)
je dobré mať postup zdokumentovaný:

```bash
# 1. Zakladne baliky, Docker, Suricata, utocne nastroje
cd ~/Documents/bp-ids/scripts
./00_install_base.sh
./01_install_attack_tools.sh          # ak prve zlyhalo

# 2. Oprava Suricata balika (systemd-tmpfiles bug v Ubuntu balicku)
./02_fix_suricata.sh

# 3. Konfiguracia Suricaty - sledovanie Docker siete, stiahnutie ET-open pravidiel
./03_configure_suricata.sh

# 4. Pristupove prava na logy (ACL, aby si nemusel stale pouzivat sudo)
./04_grant_log_access.sh

# 5. Spravne nastavenie HOME_NET (dolezite pre spravnu detekciu!)
./05_fix_homenet.sh   # prip. 05b_fix_homenet_retry.sh

# 6. Postavenie testovacej siete
cd ~/Documents/bp-ids/compose
docker compose build
docker compose up -d
```

## 5. Ako spúšťať testy (bežná prevádzka)

```bash
# Spusti vsetky utocne scenare naraz (cca 90 sekund):
docker exec attacker bash /scripts/attacks/run_all.sh

# Vyhodnot vysledky (na hostitelovi, potrebuje pristup k eve.json):
cd ~/Documents/bp-ids
python3 scripts/evaluate.py

# Zobrazit dashboard s alertami:
# otvor v prehliadaci http://localhost:5636
```

Jednotlivé scenáre sa dajú spúšťať aj samostatne, napr. len port scan:
```bash
docker exec attacker bash /scripts/attacks/01_portscan.sh
```

Reštart celého testbedu (napr. na druhý deň):
```bash
cd ~/Documents/bp-ids/compose && docker compose up -d
sudo systemctl status suricata   # over, ze Suricata bezi
```

## 6. Dosiahnuté výsledky (posledný beh)

| Scenár | Kategória | Detekované | Latencia (s) | Počet alertov | Top signatúra |
|---|---|---|---|---|---|
| baseline (benígna prevádzka) | — | — (FP zdroj) | — | **11 FP** | `GPL ICMP PING *NIX` (10×) |
| Port scan | recon | ✅ ÁNO | 0,081 | 46 | `ET SCAN Nmap Scripting Engine User-Agent Detected` |
| DoS SYN flood | dos | ✅ ÁNO | 0,267 | 1443 | `SURICATA STREAM 3way handshake...` |
| SSH brute-force | credential access | ✅ ÁNO | 0,324 | 1 | `ET SCAN LibSSH Based Frequent SSH Connections...BruteForce` |
| SQL injection (DVWA) | web | ✅ ÁNO | 0,163 | 47 | `ET WEB_SERVER SQL Errors in HTTP 200 Response` |
| Web sken (nikto) | web | ✅ ÁNO | 0,129 | 757 | `ET WEB_SERVER Script tag in URI...XSS` |

**Súhrnné metriky:**
- **Recall = 100 %** (5/5 útočných scenárov detekovaných)
- **Precision = 99,5 %** (2294 TP alertov / 11 FP alertov)
- **Latencia detekcie:** 0,08–0,32 s vo všetkých prípadoch

**Zaujímavé zistenie pre diskusiu (kap. 5):** aj bežný `ping`/`curl` vyvolal
11 alertov (najmä informačný `GPL ICMP PING *NIX`). To nie sú "škodlivé"
poplachy, ale ukazujú typický kompromis IDS nasadenia — je potrebné doladiť
závažnosť/prahy pravidiel, aby sa nízko-rizikové informačné udalosti neplietli
do rovnakej kategórie ako skutočné útoky. Dobrý priestor na odporúčanie do
záveru práce.

**Konkrétny dôkaz úspešného útoku (pre screenshoty do práce):** sqlmap pri
SQL injection scenári reálne vydumpol tabuľku `users` z DVWA databázy vrátane
hashov hesiel (`admin`, `gordonb`, `1337`, `pablo`, `smithy`) — ukazuje plný
reťazec útoku od pokusu po únik dát, a zároveň že Suricata tento útok súčasne
zachytila v reálnom čase.

## 7. Mapovanie na štruktúru práce

- **Kap. 3 (Návrh):** topológia v sekcii 1 vyššie, rozhodnutie HOME_NET/EXTERNAL_NET,
  výber piatich reprezentatívnych scenárov (recon, DoS, credential access, web/SQLi, web sken)
- **Kap. 4 (Implementácia):** sekcia 4 vyššie (presné príkazy), + odôvodnenie
  výberu Suricata/Docker/EveBox oproti alternatívam (Snort, Wazuh, ELK) kvôli
  výkonu, aktuálnosti a dostupnosti disku
- **Kap. 5 (Testovanie a vyhodnotenie):** tabuľka v sekcii 6, metodika v
  `scripts/evaluate.py` (docstring na začiatku súboru presne popisuje, ako sa
  počíta TP/FP/FN/precision/recall/latencia)

## 8. Problémy, na ktoré sme narazili (dobré ako "Diskusia"/"Limitácie" v BP)

1. **Suricata Ubuntu balík mal chybu v post-install skripte** — `/var/run/suricata`
   je na `tmpfs` a balík nemal `systemd-tmpfiles` pravidlo na jeho opätovné
   vytvorenie po reštarte. Riešenie: vlastné pravidlo v `/etc/tmpfiles.d/`.
2. **HOME_NET zahŕňal celú testovaciu sieť** (default `172.16.0.0/12` pokrýva aj
   Docker subnet 172.28.0.0/24), takže útočník aj obeť boli v tej istej "dôveryhodnej"
   zóne a pravidlá pre `EXTERNAL_NET → HOME_NET` sa vôbec nespúšťali. Riešenie:
   HOME_NET explicitne len na chránené servery.
3. **sqlmap v `--batch` režime omylom akceptoval neprihlásenú session** pri
   presmerovaní na login stránku namiesto použitia nášho prihláseného cookie.
   Riešenie: `--drop-set-cookie` flag.

## 9. Návrhy na rozšírenie (voliteľné, ak chceš bohatší dataset)

- FTP brute-force scenár (treba pridať neanonymného FTP používateľa do victim)
- Viacero úrovní intenzity DoS útoku (porovnanie latencie/počtu alertov)
- Test s vypnutými/zapnutými rôznymi kategóriami pravidiel (porovnanie
  signature-based vs. viac "anomaly" pravidiel)
- Automatizované screenshoty z EveBox dashboardu pre každý scenár
