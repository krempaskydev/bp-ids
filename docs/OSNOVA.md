# Osnova bakalárskej práce

**Názov:** Návrh a implementácia systému na detekciu prienikov (IDS) v lokálnej počítačovej sieti

## Úvod

**Hlavný cieľ:** Navrhnúť a implementovať systém na detekciu prienikov v izolovanej lokálnej sieti a overiť jeho účinnosť pri detekcii vybraných typov útokov.

**Čiastkové ciele:**
1. Analyzovať a porovnať vybrané IDS nástroje a zdôvodniť výber nástroja pre praktickú časť.
2. Navrhnúť testovaciu topológiu, umiestnenie senzora a sadu detekčných pravidiel vrátane vlastných pravidiel.
3. Implementovať riešenie vo virtualizovanom prostredí vrátane zberu a zobrazenia alertov.
4. Otestovať riešenie na definovaných scenároch a vyhodnotiť ho pomocou metrík detekcie vrátane odolnosti voči evázii.

## 1 Teoretické východiská

### 1.1 Bezpečnosť počítačových sietí
- Základné pojmy: hrozba, zraniteľnosť, riziko, bezpečnostný incident
- Dôvernosť, integrita a dostupnosť informácií

### 1.2 Typy sieťových útokov

#### 1.2.1 Prieskum siete
- Ciele a princíp prieskumu siete
- Aktívny a pasívny prieskum
- Zisťovanie dostupných zariadení, otvorených portov a prevádzkovaných služieb
- Vzťah prieskumu k taktikám Reconnaissance (TA0043) a Discovery (TA0007) v MITRE ATT&CK

#### 1.2.2 Útoky typu DoS a DDoS
- Princíp útokov typu Denial of Service
- SYN flood a zahltenie polootvorených TCP spojení
- Rozdiel medzi DoS a DDoS
- Možnosti zmierňovania a základné princípy detekcie
- Vzťah k taktike Impact (TA0040), technika Network Denial of Service (T1498)

#### 1.2.3 Útoky na autentifikáciu
- Ciele a typy útokov na prihlasovacie údaje
- Brute-force a slovníkové útoky
- Riziká slabých alebo opakovane používaných hesiel
- Vzťah k taktike Credential Access (TA0006) v MITRE ATT&CK

#### 1.2.4 Útoky na webové aplikácie
- Bežné princípy a ciele útokov na webové aplikácie
- SQL injection: príčina, princíp a možné dôsledky
- Ďalšie typy zneužitia zraniteľností webových aplikácií
- Všeobecné princípy detekcie a prevencie
- Vzťah k taktike Initial Access (TA0001), technika Exploit Public-Facing Application (T1190)

#### 1.2.5 Ďalšie sieťové hrozby
- Malware a komunikácia s riadiacim serverom (C2)
- ARP spoofing
- DNS spoofing

### 1.3 Systémy IDS a IPS
- Rozdiel medzi IDS a IPS
- Signatúrna, anomálna a hybridná detekcia
- NIDS, HIDS a hybridné riešenia
- True positive, true negative, false positive a false negative
- Logovanie, alerting a základné metriky detekcie

### 1.4 Techniky obchádzania IDS
- Časové rozloženie útoku (low-and-slow)
- Fragmentácia paketov a manipulácia s prevádzkou na úrovni protokolov
- Obfuskácia a zmena signatúr útoku
- False negative ako dôsledok evázie

### 1.5 Normy a legislatíva
> [DOPLNIŤ podľa tvojej aktuálnej verzie — v poslanej osnove táto kapitola chýbala, vedúci ju však chváli. Nižšie je rekonštrukcia podľa jeho pripomienok.]
#### 1.5.1 Normy a štandardy (ISO/IEC 27001, 27002, 27033-1, NIST SP 800-94)
#### 1.5.2 Legislatíva SR (zákon č. 69/2018 Z. z., Trestný zákon č. 300/2005 Z. z. – § 247 až 247d)
#### 1.5.3 Ochrana osobných údajov pri monitorovaní siete (GDPR, zákon č. 18/2018 Z. z.)

## 2 Analýza existujúcich riešení

### 2.1 Charakteristika vybraných nástrojov
- Účel a typ nástroja, spôsob detekcie, hlavné funkcie, výstupy, možnosti nasadenia a obmedzenia

### 2.2 Porovnanie podľa kritérií
- Voľba a zdôvodnenie kritérií, porovnávacia tabuľka:

| Kritérium | Čo porovnávať |
|---|---|
| Typ monitorovania | Sieťová prevádzka alebo koncové zariadenia |
| Hlavný účel | Detekcia, prevencia, analýza prevádzky, správa bezpečnostných udalostí |
| Spôsob detekcie | Signatúry, pravidlá, anomálie, korelácia udalostí |
| Licencia a náklady | Open source / komerčná / kombinovaný model, dostupnosť komunitnej verzie, nároky na infraštruktúru |
| Dostupnosť sád pravidiel | Dostupnosť a podmienky používania pravidiel (ET Open, Snort Community/Registered rules) |
| Reakcia na hrozbu | Upozornenie, zaznamenanie udalosti, blokovanie alebo aktívna reakcia |
| Výstupy a analýza | Upozornenia, logy, protokolové záznamy, formát a možnosti exportu |
| Náročnosť nasadenia a správy | Inštalácia, konfigurácia, ladenie pravidiel, požiadavky na správcu |
| Výkon a škálovateľnosť | Spracovanie objemu dát, vhodnosť pre veľkosť testovaného prostredia |
| Integrácia | Prepojenie s dashboardom, SIEM alebo ďalšími bezpečnostnými nástrojmi |
| Vhodnosť pre cieľ práce | Pokrytie testovacích scenárov a výskumnej otázky |

- Porovnanie nástrojov za rovnakých podmienok

### 2.3 Výber nástroja a zdôvodnenie
- Výber nástroja Suricata na základe porovnania v kapitole 2.2

## 3 Návrh riešenia

### 3.1 Topológia testovacej siete
### 3.2 Umiestnenie senzora
### 3.3 Návrh logovania, alertingu a vizualizácie
### 3.4 Návrh pravidiel (hotové sady a vlastné pravidlá)

### 3.5 Testovacie scenáre
1. Scenár 1: Nmap SYN scan so zisťovaním služieb a OS (prieskum – Active Scanning T1595, Network Service Discovery T1046)
2. Scenár 2: SYN flood – hping3 (Impact – Network Denial of Service, T1498)
3. Scenár 3: SSH brute-force – Hydra (Credential Access – Brute Force, T1110)
4. Scenár 4: SQL injection – sqlmap proti DVWA (Initial Access – Exploit Public-Facing Application, T1190)
5. Scenár 5: sken webových zraniteľností – Nikto (prieskum – Active Scanning, T1595)
6. Scenár 6: low-and-slow port scan – evázny scenár (nadväzuje na kap. 1.4), s kontrolným scanom bez spomalenia
7. Scenár 7: port scan s fragmentáciou paketov (nmap -f alebo --mtu) – evázny scenár (nadväzuje na kap. 1.4)

### 3.6 Metodika vyhodnotenia
- Generovanie benígnej (bežnej) prevádzky na pozadí (web, DNS, SSH prihlásenia, prenos súborov). Bez nej sa nedajú merať false positives.
- Ground truth: evidencia času začiatku a konca, zdrojovej IP a typu každého útoku (log z automatizačného skriptu v kap. 4.5), podľa ktorej sa alerty zaradia ako TP/FP/FN.
- Metriky: TP, FP, FN, TN, precision, recall, F1-skóre, latencia detekcie (čas od začiatku útoku po prvý alert).
- Opakovateľnosť: každý scenár spustiť viackrát (napr. 3×) za rovnakých podmienok.
- Kritériá úspešnosti: detekcia všetkých neevázných scenárov, čo najnižší počet FP po ladení pravidiel, vyhodnotenie evázných scenárov zvlášť.

## 4 Implementácia navrhnutého riešenia

### 4.1 Návrh a realizácia virtualizačného prostredia
- Charakteristika virtualizačného prostredia (kontajnerová virtualizácia – Docker)
- Konfigurácia kontajnerov a ich úloh (útočník, legitímny klient, ciele útokov)
- Návrh sieťovej topológie

### 4.2 Inštalácia a konfigurácia systému IDS
- Inštalácia zvoleného IDS
- Konfigurácia sieťového rozhrania
- Konfigurácia a overenie funkčnosti IDS

### 4.3 Nasadenie a konfigurácia detekčných pravidiel
- Implementácia základných detekčných pravidiel
- Tvorba a úprava pravidiel pre testovacie scenáre
- Konfigurácia detekcie eváznych techník

### 4.4 Zber, spracovanie a prehliadanie bezpečnostných udalostí pomocou EveBox
- Konfigurácia výstupu IDS vo formáte EVE JSON
- Inštalácia a konfigurácia EveBox
- Prehliadanie a správa detekovaných alertov
- Zdôvodnenie výberu nástroja (nenáročné nasadenie, bez plnohodnotných dashboardov) a jeho využitie v navrhnutom riešení

### 4.5 Automatizácia testovacích scenárov
- Skripty na spúšťanie scenárov a generovanie benígnej prevádzky
- Záznam ground truth (časy, IP adresy, typ útoku)
- Automatizované vyhodnotenie a opakovanie behov

## 5 Testovanie a vyhodnotenie

### 5.1 Priebeh a výsledky jednotlivých scenárov
### 5.2 Vyhodnotenie metrík (súhrnná tabuľka)
### 5.3 Ladenie pravidiel (stav pred a po)
### 5.4 Výsledky eváznych scenárov
### 5.5 Diskusia a limity riešenia
- Limity EveBox (bez plnohodnotných dashboardov), možnosť rozšírenia o ELK Stack alebo Wazuh dashboard

## Záver
- Zhodnotenie splnenia hlavného cieľa a každého čiastkového cieľa

## Zoznam použitej literatúry

## Prílohy
- Konfiguračné súbory, vlastné pravidlá, skripty (repozitár projektu)
