#!/usr/bin/env python3
"""
Vyhodnotenie ucinnosti Suricata IDS na zaklade zaznamov o spustenych
utokoch (attack_log.jsonl) a alertov, ktore vygenerovala Suricata (eve.json).

Metodika:
  - Kazdy testovaci scenar (okrem baseline_benign) ma casove okno
    [start, end + GRACE_SECONDS]. Ak sa v tomto okne objavi aspon jeden
    Suricata alert, scenar je oznaceny ako DETEKOVANY (TP na urovni scenara),
    inak ako NEDETEKOVANY (FN).
  - Latencia detekcie = cas prveho relevantneho alertu mínus zaciatok utoku.
  - Kazdy alert v okne scenara typu utok = TP (na urovni jednotlivych alertov).
  - Kazdy alert v okne baseline_benign (legitimna prevadzka) = FP.
  - Precision (na urovni alertov) = TP / (TP + FP)
  - Recall (na urovni scenarov/typov utokov) = detekovane scenare / vsetky scenare
"""
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

RESULTS_DIR = Path(__file__).resolve().parent.parent / "results"
ATTACK_LOG = RESULTS_DIR / "attack_log.jsonl"
EVE_LOG = Path("/var/log/suricata/eve.json")
GRACE_SECONDS = 3


def parse_ts(s):
    # eve.json: "2026-09-21T18:38:59.821773+0200"
    # attack_log: "2026-09-21T18:38:59.123Z"
    s = s.replace("Z", "+0000")
    if "." in s:
        head, rest = s.split(".", 1)
        # normalize fractional seconds to 6 digits + tz
        for i, ch in enumerate(rest):
            if ch in "+-":
                frac, tz = rest[:i], rest[i:]
                break
        else:
            frac, tz = rest, "+0000"
        frac = (frac + "000000")[:6]
        s = f"{head}.{frac}{tz}"
    else:
        s = s + ".000000+0000"
    return datetime.strptime(s, "%Y-%m-%dT%H:%M:%S.%f%z")


def load_scenarios():
    scenarios = {}
    with open(ATTACK_LOG) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            e = json.loads(line)
            name = e["scenario"]
            scenarios.setdefault(name, {})
            scenarios[name][e["phase"]] = e["timestamp"]
            if e["phase"] == "start":
                scenarios[name]["attack_category"] = e.get("attack_category", "?")
                scenarios[name]["tool"] = e.get("tool", "?")
    return scenarios


def load_alerts():
    alerts = []
    with open(EVE_LOG) as f:
        for line in f:
            try:
                e = json.loads(line)
            except json.JSONDecodeError:
                continue
            if e.get("event_type") != "alert":
                continue
            alerts.append({
                "ts": parse_ts(e["timestamp"]),
                "signature": e.get("alert", {}).get("signature", "?"),
                "category": e.get("alert", {}).get("category", "?"),
                "severity": e.get("alert", {}).get("severity", "?"),
                "src_ip": e.get("src_ip"),
                "dest_ip": e.get("dest_ip"),
            })
    return alerts


def main():
    if not ATTACK_LOG.exists():
        sys.exit(f"Chyba: {ATTACK_LOG} neexistuje. Najprv spusti scripts/attacks/run_all.sh")
    if not EVE_LOG.exists():
        sys.exit(f"Chyba: {EVE_LOG} neexistuje alebo nie je citatelny.")

    scenarios = load_scenarios()
    alerts = load_alerts()

    total_tp_alerts = 0
    total_fp_alerts = 0
    detected_scenarios = 0
    total_attack_scenarios = 0

    rows = []
    for name, data in scenarios.items():
        if "start" not in data or "end" not in data:
            continue
        start = parse_ts(data["start"])
        end = parse_ts(data["end"]) + timedelta(seconds=GRACE_SECONDS)
        window_alerts = [a for a in alerts if start <= a["ts"] <= end]

        is_baseline = name == "baseline_benign"

        if is_baseline:
            total_fp_alerts += len(window_alerts)
            rows.append({
                "scenario": name,
                "category": data.get("attack_category", "?"),
                "detected": "N/A",
                "latency_s": "N/A",
                "alert_count": len(window_alerts),
                "role": "FP zdroj (benigna prevadzka)",
                "top_signatures": summarize_sigs(window_alerts),
            })
        else:
            total_attack_scenarios += 1
            detected = len(window_alerts) > 0
            if detected:
                detected_scenarios += 1
                total_tp_alerts += len(window_alerts)
                latency = (window_alerts[0]["ts"] - start).total_seconds()
            else:
                latency = None
            rows.append({
                "scenario": name,
                "category": data.get("attack_category", "?"),
                "detected": "ANO" if detected else "NIE",
                "latency_s": round(latency, 3) if latency is not None else "N/A",
                "alert_count": len(window_alerts),
                "role": "utok",
                "top_signatures": summarize_sigs(window_alerts),
            })

    precision = total_tp_alerts / (total_tp_alerts + total_fp_alerts) if (total_tp_alerts + total_fp_alerts) else float("nan")
    recall = detected_scenarios / total_attack_scenarios if total_attack_scenarios else float("nan")
    fn_scenarios = total_attack_scenarios - detected_scenarios

    print_report(rows, total_tp_alerts, total_fp_alerts, detected_scenarios,
                 fn_scenarios, total_attack_scenarios, precision, recall)
    write_csv(rows)


def summarize_sigs(window_alerts, top_n=3):
    from collections import Counter
    c = Counter(a["signature"] for a in window_alerts)
    return "; ".join(f"{sig} ({cnt}x)" for sig, cnt in c.most_common(top_n))


def print_report(rows, tp, fp, detected, fn, total_scen, precision, recall):
    print("=" * 100)
    print("VYHODNOTENIE IDS - detail podla scenara")
    print("=" * 100)
    for r in rows:
        print(f"[{r['scenario']:<20}] kategoria={r['category']:<18} detekovane={r['detected']:<4} "
              f"latencia={r['latency_s']!s:<8} alertov={r['alert_count']:<4} ({r['role']})")
        if r["top_signatures"]:
            print(f"    top signatury: {r['top_signatures']}")
    print("=" * 100)
    print("SUHRNNE METRIKY")
    print("=" * 100)
    print(f"Utocne scenare spolu:              {total_scen}")
    print(f"Detekovane (TP na urovni scenara):  {detected}")
    print(f"Nedetekovane (FN na urovni scenara): {fn}")
    print(f"TP alerty (spolu, v utocnych oknach): {tp}")
    print(f"FP alerty (spolu, v baseline okne):   {fp}")
    print(f"Precision (TP/(TP+FP), na urovni alertov): {precision:.3f}" if precision == precision else "Precision: N/A")
    print(f"Recall (detekovane/vsetky scenare):        {recall:.3f}" if recall == recall else "Recall: N/A")
    print("=" * 100)


def write_csv(rows):
    import csv
    out = RESULTS_DIR / "metrics.csv"
    with open(out, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["scenario", "category", "detected", "latency_s",
                                           "alert_count", "role", "top_signatures"])
        w.writeheader()
        for r in rows:
            w.writerow(r)
    print(f"\nDetailne vysledky ulozene do: {out}")


if __name__ == "__main__":
    main()
