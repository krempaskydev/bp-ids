# BP: Návrh a implementácia IDS v lokálnej sieti — zhrnutie projektu

Tento dokument zhŕňa, čo bolo postavené, ako to funguje a ako to spustiť. Slúži
ako referencia pri písaní samotnej bakalárskej práce (kapitoly 3–5).

## 1. Architektúra

```
                    Hostiteľ (Ubuntu, tvoje PC)
                    ┌─────────────────────────────────────┐
                    │  Suricata (systemd služba)            │
                    │  sleduje rozhranie br-idsnet           │
                    │  ET-open + vlastné pravidlá (local.rules)│
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

**Prečo Docker namiesto VirtualBox/GNS3:** pri zakladaní projektu bolo k
dispozícii len ~27 GB voľného miesta, Docker kontajnery sú rádovo ľahšie ako
plné VM a zachovávajú si sieťovú izoláciu potrebnú pre realistický test.

**Dôležitý architektonický detail (dobrý bod do kap. 3):** `HOME_NET` v
Suricate je nastavený **len** na `victim` a `dvwa` (172.28.0.10,
172.28.0.11). Útočník (172.28.0.20) tak spadá pod `EXTERNAL_NET` — presne ako
v reálnom nasadení, kde útočník prichádza "zvonka" na chránené servery. Veľa
ET-open pravidiel je písaných práve pre smer `EXTERNAL_NET → HOME_NET` a bez
tohto nastavenia by vôbec nefungovali (pozri sekciu 8 — dokumentované chyby).

## 2. Komponenty

| Komponent | Nástroj | Poznámka |
|---|---|---|
| IDS jadro | Suricata 8.0.7 | af-packet mód, beží ako systemd služba priamo na hostiteľovi |
| Pravidlá | Emerging Threats Open (ET-open) + vlastné (`local.rules`) | 52 828 ET pravidiel + 2 vlastné (spolu 52 830) |
| Dashboard | EveBox 0.29.0 | Docker kontajner, SQLite backend (bez ťažkého ELK), http://localhost:5636 |
| Testovacia sieť | Docker Compose | 3 kontajnery: victim, dvwa, attacker |
| Cieľ útokov | victim (vlastný Ubuntu image) | SSH (slabé heslo testuser/testpass123), FTP (anonymous), Apache |
| Cieľ webových útokov | dvwa (`vulnerables/web-dvwa`) | DVWA v1.10, security level "low" |
| Útočné nástroje | nmap, hping3, hydra, nikto, sqlmap | v attacker kontajneri, izolované od hostiteľa |
| Vyhodnotenie | `scripts/evaluate.py` | počíta TP/FP/FN, precision, recall, latenciu |

## 3. Vlastné Suricata pravidlá (`rules/local.rules`)

Nad rámec nasadenia hotového ET-open rulesetu obsahuje projekt aj **dve
vlastné pravidlá**, ktoré demonštrujú samostatný "implementačný" prínos:

1. **`LOCAL POLICY External access to DVWA vulnerable test endpoint`** —
   politikové pravidlo: akýkoľvek prístup z `EXTERNAL_NET` na cestu
   `/vulnerabilities/` je v produkčnom nasadení podozrivý sám o sebe, bez
   ohľadu na konkrétny payload (vývojárske/demo endpointy by nemali byť
   prístupné zvonka).
2. **`LOCAL POLICY Possible fast TCP port scan (threshold)`** — prahové
   pravidlo: 5 a viac SYN paketov z jedného zdroja voči chráneným hostom
   behom 5 sekúnd. Používa `threshold:type both` (nie `detection_filter` —
   ten by pri SYN floode vygeneroval alert na *každý* ďalší paket po
   dosiahnutí prahu, čo sme si počas ladenia reálne overili: prvá verzia
   pravidla vyprodukovala 2,3 milióna alertov na jeden 20-sekundový flood).
   Práve toto pravidlo je zámerne navrhnuté tak, aby ho útočník mohol
   obísť spomalením — pozri scenár 6 nižšie.

## 4. Adresárová štruktúra

```
bp-ids/
├── compose/
│   ├── docker-compose.yml      # definícia siete a kontajnerov
│   ├── victim/Dockerfile       # SSH+FTP+HTTP server so slabými heslami
│   └── attacker/Dockerfile     # nmap, hping3, hydra, nikto, sqlmap
├── rules/
│   └── local.rules              # vlastné Suricata pravidlá (viz sekcia 3)
├── scripts/
│   ├── 00-08_*.sh                # jednorazové inštalačné/opravné skripty (host)
│   ├── attacks/
│   │   ├── lib.sh                 # spoločné logovanie časov útokov
│   │   ├── 00_baseline.sh         # benígna prevádzka (meranie FP, ~2-3 min)
│   │   ├── 01_portscan.sh         # nmap SYN scan + service/OS detekcia
│   │   ├── 02_dos_synflood.sh     # hping3 SYN flood (20s)
│   │   ├── 03_ssh_bruteforce.sh   # hydra brute-force na SSH
│   │   ├── 04_web_sqli.sh         # sqlmap SQL injection na DVWA
│   │   ├── 05_web_scan_nikto.sh   # nikto sken zraniteľností
│   │   ├── 06_portscan_slow.sh    # "low-and-slow" scan (zámerne NEdetekovaný)
│   │   ├── dvwa_setup.sh          # pomocný: prihlásenie + reset DB v DVWA
│   │   └── run_all.sh             # spustí všetky scenáre za sebou
│   └── evaluate.py               # vyhodnotenie: TP/FP/FN, precision, recall, latencia
├── results/
│   ├── attack_log.jsonl         # "ground truth" - presné časy každého útoku
│   └── metrics.csv              # výstup evaluate.py
└── docs/                        # voľný priečinok pre tvoje poznámky/screenshoty
```

## 5. Ako to spustiť odznova (setup)

```bash
# 1. Zakladne baliky, Docker, Suricata, utocne nastroje
cd ~/Documents/bp-ids/scripts
./00_install_base.sh
./01_install_attack_tools.sh

# 2. Oprava Suricata balika (systemd-tmpfiles bug v Ubuntu balicku)
./02_fix_suricata.sh

# 3. Konfiguracia Suricaty - sledovanie Docker siete, stiahnutie ET-open pravidiel
./03_configure_suricata.sh

# 4. Pristupove prava na logy (ACL, aby si nemusel stale pouzivat sudo)
./04_grant_log_access.sh

# 5. Spravne nastavenie HOME_NET (dolezite pre spravnu detekciu!)
./05_fix_homenet.sh   # prip. 05b_fix_homenet_retry.sh podla indentacie yaml

# 6. GitHub CLI + prihlasenie (ak chces pushovat zmeny)
./06_install_gh_and_login.sh

# 7. Vlastne pravidla + log rotation + cisty log
./07_apply_fixes.sh    # prip. 07b_fix_local_rules.sh + 08_reload_rules.sh
                        # ak sa pri prvom pokuse nepodari nacitat pravidla

# 8. Postavenie testovacej siete
cd ~/Documents/bp-ids/compose
docker compose build
docker compose up -d
```

## 6. Ako spúšťať testy (bežná prevádzka)

```bash
# Ak boli kontajnery vypnute (napr. po restarte PC), najprv:
cd ~/Documents/bp-ids/compose && docker compose up -d

# Spusti vsetky utocne scenare naraz (cca 3-4 minuty vratane baseline):
docker exec attacker bash /scripts/attacks/run_all.sh

# Vyhodnot vysledky (na hostitelovi, potrebuje pristup k eve.json):
cd ~/Documents/bp-ids
python3 scripts/evaluate.py

# Zobrazit dashboard s alertami:
# otvor v prehliadaci http://localhost:5636
```

## 7. Dosiahnuté výsledky (finálny čistý beh)

| Scenár | Kategória | Detekované | Latencia (s) | Počet alertov | Top signatúra |
|---|---|---|---|---|---|
| baseline (benígna prevádzka, ~3 min) | — | — (FP zdroj) | — | **66 FP** | `GPL ICMP PING *NIX` (30×), `SURICATA HTTP Response excessive header repetition` (30×) |
| Port scan | recon | ✅ ÁNO | 0,101 | 47 | `ET SCAN Nmap Scripting Engine User-Agent Detected` |
| **Low-and-slow port scan** | recon (evasion) | ❌ **NIE** | — | **0** | *(zámerne — FN scenár, viz sekcia 9)* |
| DoS SYN flood | dos | ✅ ÁNO | 0,023 | 1728 | `SURICATA STREAM 3way handshake...` |
| SSH brute-force | credential access | ✅ ÁNO | 0,312 | 2 | `ET SCAN LibSSH...BruteForce` + vlastné `LOCAL POLICY` pravidlo |
| SQL injection (DVWA) | web | ✅ ÁNO | 0,155 | 142 | vlastné `LOCAL POLICY External access to DVWA...` (89×) + `ET WEB_SERVER SQL Errors` |
| Web sken (nikto) | web | ✅ ÁNO | 0,124 | 759 | `ET WEB_SERVER Script tag in URI...XSS` |

**Súhrnné metriky:**
- **Recall = 5/6 = 83,3 %** (jeden scenár — low-and-slow scan — bol zámerne
  navrhnutý tak, aby unikol detekcii)
- **Precision = 97,6 %** (2678 TP alertov / 66 FP alertov, oba merané na
  úrovni jednotlivých alertov — pozri metodologické obmedzenia nižšie)
- **Latencia detekcie:** 0,02–0,31 s pri všetkých úspešne detekovaných útokoch

**Konkrétny dôkaz úspešného útoku (pre screenshoty do práce):** sqlmap pri
SQL injection scenári reálne vydumpol tabuľku `users` z DVWA databázy vrátane
hashov hesiel (`admin`, `gordonb`, `1337`, `pablo`, `smithy`) — ukazuje plný
reťazec útoku od pokusu po únik dát, a zároveň že Suricata tento útok súčasne
zachytila v reálnom čase (vrátane vlastného politikového pravidla).

## 8. Metodologické obmedzenia (dôležité pre obhajobu!)

Pri code review tejto práce padli viaceré opodstatnené pripomienky k
metodike merania. Namiesto ich zametenia pod koberec ich tu explicitne
pomenúvame — presne toto komisia oceňuje viac než falošne dokonalé čísla:

1. **Precision sa počíta na úrovni jednotlivých alertov, nie útokov.**
   TP = "akýkoľvek alert vygenerovaný v časovom okne známeho útoku". To
   znamená, že aj menej relevantný/redundantný alert počas útoku sa ráta ako
   true positive. Číslo 97,6 % je preto potrebné interpretovať ako
   "podiel alertov vzniknutých počas útokov voči alertom vzniknutým počas
   legitímnej prevádzky", nie ako presnosť klasifikácie jednotlivých typov
   útokov.
2. **Recall na úrovni scenárov je binárny (detekované áno/nie), nie
   klasifikačný.** Nehovorí nič o tom, či IDS rozpoznal *správny* typ
   útoku — len či sa v danom okne objavil aspoň jeden alert. Čestnejšia
   formulácia: "5 z 6 testovaných tried útokov vyvolalo aspoň jeden
   relevantný alert".
3. **Baseline (FP meranie) bol pôvodne len ~10 sekúnd** (prvá verzia), čo
   bola príliš malá vzorka na vierohodný odhad false-positive rate. Bol
   predĺžený na ~3 minúty s rozmanitejšou prevádzkou (HTTP requesty na
   viacero stránok, opakované legitímne SSH prihlásenia, anonymný FTP
   listing).
4. **Iba signature/threshold-based detekcia.** Práca hovorí o "návrhu a
   implementácii IDS", ale jadrom je nasadenie a konfigurácia hotového IDS
   (Suricata) s prevažne hotovými pravidlami (ET-open). Vlastný prínos je v
   architektúre testbedu, voľbe HOME_NET/EXTERNAL_NET, dvoch vlastných
   pravidlách (sekcia 3) a návrhu evázneho scenára (sekcia 9) — nie vo
   vlastnom detekčnom algoritme. Táto hranica by mala byť v práci explicitne
   pomenovaná, nie skrývaná.
5. **sqlmap medzi behmi cachuje nájdenú injekčnú techniku** (v
   `~/.local/share/sqlmap`) — opakovaný beh proti tomu istému cieľu preskočí
   heuristické testovanie a trvá len desatiny sekundy namiesto ~11 s plného
   testu. Opravené pomocou `--flush-session`, aby bolo časovanie
   reprodukovateľné medzi behmi.

## 9. Scenár 6: Low-and-slow port scan (zámerný False Negative)

Na odporúčanie z code review bol pridaný scenár, ktorý IDS **cielene
nezachytí** — bez toho totiž recall 100 % pôsobí triviálne (pri 52 830
pravidlách a "hlučných" nástrojoch typu nmap/nikto je takmer isté, že aspoň
jedno pravidlo niečo zachytí).

**Princíp:** `06_portscan_slow.sh` spúšťa holý SYN scan (`nmap -sS`, bez
`-sV/-A`, teda bez NSE/User-Agent stôp) s vloženým odstupom 3 sekundy medzi
paketmi (`--scan-delay 3s`). Naše vlastné prahové pravidlo (sekcia 3, bod 2)
vyžaduje 5 SYN paketov v 5-sekundovom okne — pri 3s odstupe medzi paketmi sa
tento prah nikdy nedosiahne.

**Výsledok:** 0 alertov, útok prešiel bez povšimnutia — reálny, poctivo
nameraný False Negative.

**Prečo je to hodnotné pre BP:** demonštruje to konkrétne a merateľné
obmedzenie signature/threshold-based prístupu, ktoré je vhodné rozvinúť v
diskusii/závere práce — napr. že doplnenie anomaly-based alebo
behaviorálnej detekcie (dlhodobé sledovanie počtu unikátnych portov za
hodinu/deň, nie len za sekundy) by tento typ útoku odhalilo, kým čisto
signature-based Suricata s krátkymi prahovými oknami nie.

## 10. Mapovanie na štruktúru práce

- **Kap. 3 (Návrh):** topológia v sekcii 1, rozhodnutie HOME_NET/EXTERNAL_NET,
  výber šiestich reprezentatívnych scenárov (recon, recon-evasion, DoS,
  credential access, web/SQLi, web sken), návrh vlastných pravidiel (sekcia 3)
- **Kap. 4 (Implementácia):** sekcia 5 (presné príkazy), odôvodnenie výberu
  Suricata/Docker/EveBox oproti alternatívam (Snort, Wazuh, ELK) kvôli
  výkonu, aktuálnosti a dostupnosti disku, popis vlastných pravidiel
- **Kap. 5 (Testovanie a vyhodnotenie):** tabuľka v sekcii 7, metodika v
  `scripts/evaluate.py` (docstring na začiatku súboru), **explicitne
  pomenované obmedzenia v sekcii 8** — presne materiál na podkapitolu
  "Diskusia výsledkov" zo zadania

## 11. Problémy, na ktoré sme narazili (dobré ako "Diskusia"/"Limitácie" v BP)

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
4. **`eve.json` narástol za 2 dni nepretržitej prevádzky na 4,3 GB** — chýbala
   log rotation. Riešenie: `rotate-interval: day` v `suricata.yaml`.
5. **Vlastné prahové pravidlo pôvodne používalo `detection_filter`**, ktoré
   generuje alert na *každý* ďalší paket po dosiahnutí prahu (nie raz za
   okno) — pri 20-sekundovom SYN floode to spôsobilo 2,3 milióna alertov.
   Riešenie: `threshold:type both` namiesto `detection_filter`.
6. **Nekonzistentné čísla medzi README a `metrics.csv`** — pri jednom z
   predchádzajúcich behov bolo README aktualizované ručne z terminálového
   výstupu a následne prebehol ešte jeden (nezdokumentovaný) beh, ktorého
   výsledky sa dostali do commitnutých súborov namiesto pôvodných. Odhalené
   pri externom code review. Poučenie: čísla do práce preberať vždy priamo
   z `metrics.csv` tesne pred odovzdaním, nikdy ručne prepisovať z chatu/
   terminálu.

## 12. Návrhy na ďalšie rozšírenie (voliteľné)

- FTP brute-force scenár (treba pridať neanonymného FTP používateľa do victim)
- Porovnanie s vypnutými/zapnutými rôznymi kategóriami ET pravidiel
- Porovnanie Suricata vs. Snort/Zeek na tom istom datasete (vyššia námaha)
- Jednoduchý anomaly/prahový detektor ako doplnok k signature-based prístupu,
  porovnanie účinnosti (vyššia námaha — priamo nadväzuje na zistenie v
  sekcii 9)
- Automatizované screenshoty z EveBox dashboardu pre každý scenár
