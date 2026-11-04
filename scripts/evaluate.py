#!/usr/bin/env python3
"""
Vyhodnotenie ucinnosti Suricata IDS pre jeden beh experimentu (kap. 3.6, 5.1, 5.2).

Vstupy:
  <run>/attack_log.jsonl  ground truth - cas zaciatku/konca, ciel, nastroj
                          a MITRE technika kazdeho scenara (zapisuje lib.sh)
  <run>/meta.json         profil pravidiel, cas behu benignej prevadzky
                          (zapisuje run_experiment.sh; nepovinny)
  /var/log/suricata/eve.json (+ eve.json.1 po rotacii)

Priradenie alertu (podla IP, nie len podla casu):
  - alert s IP utocnika 172.28.0.20 v okne scenara [start, end + GRACE]
      -> patri danemu scenaru (TP alert)
  - alert s IP klienta 172.28.0.30 (benigna prevadzka na pozadi) kedykolvek
      -> FP alert
  - alert s IP utocnika mimo okien (napr. prihlasenie do DVWA v dvwa_setup.sh)
      -> "nepriradeny", vykazuje sa zvlast a do metrik sa nezapocitava

Metriky na urovni udalosti (zakladne vyhodnotenie):
  - pozitivne vzorky = utocne scenare. Scenar je DETEKOVANY (TP), ak v jeho
    okne vznikol aspon 1 alert utocnika, inak FN.
  - negativne vzorky = 10-sekundove sloty cisteho benigneho okna
    (baseline_benign, utocnik je necinny). Slot s aspon 1 alertom = FP,
    slot bez alertu = TN.
  - precision = TP/(TP+FP), recall = TP/(TP+FN), F1 = 2PR/(P+R),
    FPR = FP/(FP+TN)
  - evazne scenare (kategoria *_evasion) sa do tychto metrik NEZAPOCITAVAJU
    a vyhodnocuju sa zvlast (kriterium uspesnosti z kap. 3.6).

Doplnkove metriky:
  - latencia detekcie = cas prveho alertu utocnika minus zaciatok scenara
  - precision na urovni alertov = TP alerty / (TP alerty + FP alerty)
  - FP alerty za minutu benignej prevadzky

Vystupy do <run>/: metrics.csv (po scenaroch), signatures.csv (uplny rozpis
signatur, nie len top-N), summary.json (suhrnne metriky pre aggregate.py).

Pouzitie: python3 scripts/evaluate.py --run results/runs/<id>
"""
import argparse
import csv
import glob
import json
import sys
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from pathlib import Path

ATTACKER_IP = "172.28.0.20"
CLIENT_IP = "172.28.0.30"
GRACE_SECONDS = 3
SLOT_SECONDS = 10
MARGIN = timedelta(seconds=60)


def parse_ts(s):
    # eve.json: "2026-09-21T18:38:59.821773+0200" ; attack_log: "...59.123Z"
    s = s.replace("Z", "+0000")
    if "." in s:
        head, rest = s.split(".", 1)
        for i, ch in enumerate(rest):
            if ch in "+-":
                frac, tz = rest[:i], rest[i:]
                break
        else:
            frac, tz = rest, "+0000"
        s = f"{head}.{(frac + '000000')[:6]}{tz}"
    else:
        s = s[:19] + ".000000" + (s[19:] or "+0000")
    return datetime.strptime(s, "%Y-%m-%dT%H:%M:%S.%f%z")


def scenario_type(category):
    if category == "none":
        return "baseline"
    if category.endswith("_evasion"):
        return "evasion"
    return "core"


def load_scenarios(path):
    sc = {}
    order = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            e = json.loads(line)
            name = e["scenario"]
            if name not in sc:
                sc[name] = {}
                order.append(name)
            sc[name][e["phase"]] = parse_ts(e["timestamp"])
            if e["phase"] == "start":
                for k in ("attack_category", "tool", "mitre", "dst_ip"):
                    sc[name][k] = e.get(k, "")
    return [(n, sc[n]) for n in order if "start" in sc[n] and "end" in sc[n]]


def load_alerts(eve_paths, t_from, t_to):
    alerts = []
    for p in eve_paths:
        with open(p, errors="replace") as f:
            for line in f:
                if '"event_type":"alert"' not in line:
                    continue
                try:
                    e = json.loads(line)
                    ts = parse_ts(e["timestamp"])
                except (json.JSONDecodeError, KeyError, ValueError):
                    continue
                if not (t_from <= ts <= t_to):
                    continue
                src, dst = e.get("src_ip"), e.get("dest_ip")
                if ATTACKER_IP in (src, dst):
                    role = "attack"
                elif CLIENT_IP in (src, dst):
                    role = "benign"
                else:
                    role = "other"
                a = e.get("alert", {})
                alerts.append({"ts": ts, "sid": a.get("signature_id"),
                               "signature": a.get("signature", "?"),
                               "role": role, "src": src, "dst": dst,
                               "dport": e.get("dest_port")})
    alerts.sort(key=lambda x: x["ts"])
    return alerts


def ratio(a, b):
    return a / b if b else None


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    ap.add_argument("--run", required=True, help="adresar behu, napr. results/runs/before_r1_...")
    ap.add_argument("--eve", nargs="*", default=None,
                    help="cesty k eve.json (default: /var/log/suricata/eve.json*)")
    args = ap.parse_args()

    run = Path(args.run)
    log = run / "attack_log.jsonl"
    if not log.exists():
        sys.exit(f"Chyba: {log} neexistuje")
    meta = json.loads((run / "meta.json").read_text()) if (run / "meta.json").exists() else {}
    eve_paths = args.eve or sorted(p for p in glob.glob("/var/log/suricata/eve.json*")
                                   if not p.endswith(".gz"))
    if not eve_paths:
        sys.exit("Chyba: nenasiel sa ziadny eve.json")

    scenarios = load_scenarios(log)
    if not scenarios:
        sys.exit("Chyba: attack_log neobsahuje ziadny kompletny scenar")
    run_start = min(d["start"] for _, d in scenarios)
    run_end = max(d["end"] for _, d in scenarios) + timedelta(seconds=GRACE_SECONDS)
    benign_start = parse_ts(meta["benign_start"]) if "benign_start" in meta else run_start
    benign_end = parse_ts(meta["benign_end"]) if "benign_end" in meta else run_end
    alerts = load_alerts(eve_paths, min(run_start, benign_start) - MARGIN,
                         max(run_end, benign_end) + MARGIN)

    rows, sig_rows = [], []
    attributed = set()
    tp_alerts = 0
    core_tp = core_fn = 0
    fp_slots = tn_slots = 0
    evasion = {}
    latencies = {}
    baseline_nonclient = []   # alerty v cistom benignom okne, ktore nemaju IP klienta

    for name, d in scenarios:
        stype = scenario_type(d.get("attack_category", ""))
        start, end = d["start"], d["end"] + timedelta(seconds=GRACE_SECONDS)
        in_win = [a for a in alerts if start <= a["ts"] <= end]

        if stype == "baseline":
            # sloty cisteho benigneho okna: FP / TN
            t = d["start"]
            while t < d["end"]:
                t2 = min(t + timedelta(seconds=SLOT_SECONDS), d["end"])
                if any(t <= a["ts"] < t2 for a in in_win):
                    fp_slots += 1
                else:
                    tn_slots += 1
                t = t2
            win_alerts = in_win
            attributed.update(id(a) for a in in_win)
            baseline_nonclient += [a for a in in_win if a["role"] != "benign"]
            detected, latency = "N/A", None
        else:
            win_alerts = [a for a in in_win if a["role"] == "attack"]
            attributed.update(id(a) for a in win_alerts)
            tp_alerts += len(win_alerts)
            det = bool(win_alerts)
            latency = (win_alerts[0]["ts"] - d["start"]).total_seconds() if det else None
            detected = "ANO" if det else "NIE"
            latencies[name] = latency
            if stype == "core":
                core_tp += det
                core_fn += not det
            else:
                evasion[name] = det

        c = Counter((a["sid"], a["signature"]) for a in win_alerts)
        rows.append({
            "scenario": name, "type": stype, "category": d.get("attack_category", ""),
            "mitre": d.get("mitre", ""), "tool": d.get("tool", ""),
            "duration_s": round((d["end"] - d["start"]).total_seconds(), 1),
            "detected": detected,
            "latency_s": round(latency, 3) if latency is not None else "N/A",
            "alerts": len(win_alerts),
            "benign_alerts_in_window": sum(a["role"] == "benign" for a in in_win),
            "distinct_signatures": len(c),
            "top_signatures": "; ".join(f"{s} ({n}x)" for (_, s), n in c.most_common(5)),
        })
        for (sid, sig), n in c.most_common():
            sig_rows.append({"scenario": name, "role": "baseline" if stype == "baseline" else "attack",
                             "sid": sid, "signature": sig, "count": n})

    benign = [a for a in alerts if a["role"] == "benign" and benign_start <= a["ts"] <= benign_end + timedelta(seconds=GRACE_SECONDS)]
    benign += baseline_nonclient   # aj tieto su FP - utocnik je v baseline necinny
    unattributed = [a for a in alerts if a["role"] == "attack" and id(a) not in attributed
                    and run_start <= a["ts"] <= run_end]
    for label, lst in (("benign_background", benign), ("unattributed_attacker", unattributed)):
        for (sid, sig), n in Counter((a["sid"], a["signature"]) for a in lst).most_common():
            sig_rows.append({"scenario": label, "role": "benign" if label.startswith("benign") else "unattributed",
                             "sid": sid, "signature": sig, "count": n})

    precision = ratio(core_tp, core_tp + fp_slots)
    recall = ratio(core_tp, core_tp + core_fn)
    f1 = ratio(2 * precision * recall, precision + recall) if precision is not None and recall is not None else None
    benign_min = (benign_end - benign_start).total_seconds() / 60
    summary = {
        "run": run.name,
        "profile": meta.get("profile", "?"),
        "core_scenarios": core_tp + core_fn,
        "TP": core_tp, "FN": core_fn, "FP": fp_slots, "TN": tn_slots,
        "precision": precision, "recall": recall, "f1": f1,
        "fpr": ratio(fp_slots, fp_slots + tn_slots),
        "evasion": {k: bool(v) for k, v in evasion.items()},
        "tp_alerts": tp_alerts,
        "fp_alerts": len(benign),
        "alert_precision": ratio(tp_alerts, tp_alerts + len(benign)),
        "fp_alerts_per_min": ratio(len(benign), benign_min),
        "benign_minutes": round(benign_min, 2),
        "unattributed_attacker_alerts": len(unattributed),
        "other_alerts": sum(a["role"] == "other" for a in alerts),
        "latency_s": latencies,
        "scenarios": {r["scenario"]: {"detected": r["detected"], "alerts": r["alerts"],
                                       "type": r["type"]} for r in rows},
    }

    with open(run / "metrics.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)
    with open(run / "signatures.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["scenario", "role", "sid", "signature", "count"])
        w.writeheader()
        w.writerows(sig_rows)
    (run / "summary.json").write_text(json.dumps(summary, indent=2, ensure_ascii=False))
    print_report(rows, summary)
    print(f"\nVystupy: {run}/metrics.csv, signatures.csv, summary.json")


def fmt(x, pct=False):
    if x is None:
        return "N/A"
    return f"{x * 100:.1f} %" if pct else f"{x:.3f}"


def print_report(rows, s):
    line = "=" * 100
    print(line)
    print(f"VYHODNOTENIE IDS - beh {s['run']} (profil: {s['profile']})")
    print(line)
    for r in rows:
        print(f"[{r['scenario']:<24}] {r['type']:<8} detekovane={r['detected']:<4} "
              f"latencia={r['latency_s']!s:<7} alertov={r['alerts']:<5} "
              f"(benign v okne: {r['benign_alerts_in_window']})")
        if r["top_signatures"]:
            print(f"    {r['top_signatures']}")
    print(line)
    print("SUHRNNE METRIKY (zakladne scenare, uroven udalosti)")
    print(f"  TP={s['TP']}  FN={s['FN']}  FP={s['FP']} (10s slotov)  TN={s['TN']}")
    print(f"  precision={fmt(s['precision'])}  recall={fmt(s['recall'])}  "
          f"F1={fmt(s['f1'])}  FPR={fmt(s['fpr'])}")
    print("EVAZNE SCENARE (vyhodnotene zvlast)")
    for k, v in s["evasion"].items():
        print(f"  {k:<26} {'DETEKOVANY' if v else 'NEDETEKOVANY (FN)'}")
    print("DOPLNKOVE")
    print(f"  TP alerty={s['tp_alerts']}  FP alerty={s['fp_alerts']}  "
          f"precision na urovni alertov={fmt(s['alert_precision'])}")
    print(f"  FP alertov za minutu benignej prevadzky={fmt(s['fp_alerts_per_min'])} "
          f"({s['benign_minutes']} min)")
    print(f"  nepriradene alerty utocnika (mimo okien)={s['unattributed_attacker_alerts']}  "
          f"ine IP={s['other_alerts']}")
    print(line)


if __name__ == "__main__":
    main()
