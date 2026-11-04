#!/usr/bin/env python3
"""
Agregacia opakovanych behov (kap. 3.6 opakovatelnost, 5.2 suhrnna tabulka,
5.3 porovnanie pred/po ladeni, 5.4 evazne scenare).

Nacita results/runs/<profil>_r*/summary.json a pre kazdy profil vypocita
priemer a smerodajnu odchylku metrik, mieru detekcie scenarov (k/N) a
latenciu. Ak existuju oba profily (before, after), vytvori aj porovnanie.

Vystupy: results/aggregate_<profil>.md, results/aggregate_<profil>.json,
         results/comparison.md
Pouzitie: python3 scripts/aggregate.py
"""
import json
import statistics as st
from collections import defaultdict
from pathlib import Path

RESULTS = Path(__file__).resolve().parent.parent / "results"
METRICS = [("TP", "TP (detekovane zakladne scenare)", False),
           ("FN", "FN", False),
           ("FP", "FP (10 s sloty s alertom v benignom okne)", False),
           ("TN", "TN (10 s sloty bez alertu)", False),
           ("precision", "Precision", True),
           ("recall", "Recall", True),
           ("f1", "F1-skore", True),
           ("fpr", "FPR (miera falosnych poplachov)", True),
           ("alert_precision", "Precision na urovni alertov", True),
           ("fp_alerts", "FP alerty spolu", False),
           ("fp_alerts_per_min", "FP alerty za minutu", False)]


def ms(vals, pct=False):
    vals = [v for v in vals if v is not None]
    if not vals:
        return "N/A", None
    m = st.mean(vals)
    sd = st.stdev(vals) if len(vals) > 1 else 0.0
    if pct:
        return f"{m * 100:.1f} % ± {sd * 100:.1f}", m
    return f"{m:.2f} ± {sd:.2f}", m


def aggregate(profile, summaries):
    n = len(summaries)
    out = {"profile": profile, "runs": n, "metrics": {}, "scenarios": {}}
    for key, _, pct in METRICS:
        txt, mean = ms([s.get(key) for s in summaries], pct)
        out["metrics"][key] = {"text": txt, "mean": mean}
    names = []
    for s in summaries:
        for k in s["scenarios"]:
            if k not in names:
                names.append(k)
    for name in names:
        per = [s["scenarios"].get(name) for s in summaries]
        stype = next((p["type"] for p in per if p), "?")
        det = sum(1 for p in per if p and p["detected"] == "ANO")
        lat_txt, _ = ms([s["latency_s"].get(name) for s in summaries])
        al_txt, _ = ms([p["alerts"] for p in per if p])
        out["scenarios"][name] = {"type": stype, "detected": det, "runs": n,
                                  "latency": lat_txt, "alerts": al_txt}
    return out


def to_md(a):
    lines = [f"# Agregovane vysledky - profil `{a['profile']}` ({a['runs']} behov)", "",
             "Hodnoty: priemer ± smerodajna odchylka cez behy.", "",
             "## Scenare", "",
             "| Scenar | Typ | Detekovane | Latencia (s) | Pocet alertov |",
             "|---|---|---|---|---|"]
    for name, s in a["scenarios"].items():
        det = "—" if s["type"] == "baseline" else f"{s['detected']}/{s['runs']}"
        lat = "—" if s["type"] == "baseline" else s["latency"]
        lines.append(f"| {name} | {s['type']} | {det} | {lat} | {s['alerts']} |")
    lines += ["", "## Suhrnne metriky (zakladne scenare; evazne su vyhodnotene zvlast)", "",
              "| Metrika | Hodnota |", "|---|---|"]
    for key, label, _ in METRICS:
        lines.append(f"| {label} | {a['metrics'][key]['text']} |")
    return "\n".join(lines) + "\n"


def comparison(b, a):
    lines = ["# Porovnanie pred / po ladeni pravidiel (kap. 5.3, 5.4)", "",
             f"Pred: {b['runs']} behov, po: {a['runs']} behov.", "",
             "| Metrika | Pred ladenim | Po ladeni |", "|---|---|---|"]
    for key, label, _ in METRICS:
        lines.append(f"| {label} | {b['metrics'][key]['text']} | {a['metrics'][key]['text']} |")
    lines += ["", "## Detekcia scenarov", "",
              "| Scenar | Typ | Pred | Po |", "|---|---|---|---|"]
    for name, s in b["scenarios"].items():
        if s["type"] == "baseline":
            continue
        s2 = a["scenarios"].get(name, {})
        lines.append(f"| {name} | {s['type']} | {s['detected']}/{s['runs']} | "
                     f"{s2.get('detected', '?')}/{s2.get('runs', '?')} |")
    return "\n".join(lines) + "\n"


def main():
    groups = defaultdict(list)
    for p in sorted((RESULTS / "runs").glob("*/summary.json")):
        s = json.loads(p.read_text())
        groups[s.get("profile", "?")].append(s)
    if not groups:
        print("Ziadne behy v results/runs/*/summary.json")
        return
    aggs = {}
    for profile, summaries in groups.items():
        a = aggregate(profile, summaries)
        aggs[profile] = a
        (RESULTS / f"aggregate_{profile}.json").write_text(json.dumps(a, indent=2, ensure_ascii=False))
        md = to_md(a)
        (RESULTS / f"aggregate_{profile}.md").write_text(md)
        print(md)
    if "before" in aggs and "after" in aggs:
        c = comparison(aggs["before"], aggs["after"])
        (RESULTS / "comparison.md").write_text(c)
        print(c)


if __name__ == "__main__":
    main()
