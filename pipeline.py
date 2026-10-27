"""ImmuneFleet data pipeline: runs the real steps on CAN-style traffic.
detect (statistical, on-car) -> draft rule -> validate -> quorum -> peer test -> protection test.
Frames are tuples (time_s, can_id, label) where label 1 = injected attack frame."""
import json, random, re
from collections import Counter, defaultdict

THREATS = {"CAN_FLOOD", "SPOOFING", "REPLAY"}
ACTIONS = {"BLOCK", "ALERT", "RATE_LIMIT"}
ID_RE = re.compile(r"^0x[0-9A-F]{3}$")
SAFETY_CRITICAL = {"0x0B0"}
LINE_BYTES = 53          # approx. size of one logged CAN frame as text
WIN = 0.5                # detection window (s)

# ---------- data ----------
PERIODS = {0x316: .01, 0x2C0: .01, 0x153: .01, 0x18F: .01, 0x260: .01, 0x2A0: .01,
           0x164: .02, 0x220: .02, 0x329: .02, 0x370: .1, 0x4F0: .1, 0x545: .1}

def gen_vehicle(seed, attack="dos", dur=20.0, a0=8.0, a1=13.0):
    """Synthetic vehicle: attack-free recording + a traffic recording that contains an attack."""
    rnd = random.Random(seed)
    def normal():
        out = []
        for cid, p in PERIODS.items():
            t = rnd.uniform(0, p)
            while t < dur:
                out.append((t, cid, 0)); t += p * rnd.uniform(0.985, 1.015)
        return out
    normal_rec, traffic = sorted(normal()), normal()
    t = a0
    while t < a1:
        traffic.append((t, 0x000 if attack == "dos" else 0x316, 1))
        t += 0.0003 if attack == "dos" else 0.001
    traffic.sort()
    return {"normal": normal_rec, "traffic": traffic, "raw_bytes": len(traffic) * LINE_BYTES}

def synthetic_fleet(attack="dos", n=5):
    return [dict(gen_vehicle(100 + i, attack), name=f"Car {i+1}") for i in range(n)]

def parse_frames(text, max_frames=200_000):
    """Parses two common layouts: CSV 'time,ID,DLC,bytes...,R/T' and 'Timestamp: x ID: y ...'."""
    out, csv_re = [], re.compile(r"Timestamp:\s*([\d.]+)\s+ID:\s*([0-9a-fA-F]+)")
    for line in text.splitlines():
        m = csv_re.search(line)
        try:
            if m: t, cid, lab = float(m.group(1)), int(m.group(2), 16), 0
            else:
                p = line.strip().split(",")
                t, cid, lab = float(p[0]), int(p[1], 16), 1 if p[-1].strip().upper() == "T" else 0
        except (ValueError, IndexError):
            continue
        out.append((t, cid, lab))
        if len(out) >= max_frames: break
    return out

def fleet_from_real(normal, attack, n=5):
    """Slices one real attack recording and one attack-free recording into n 'vehicles'.
    The slices come from the same car, so they are NOT independent vehicles."""
    def chunks(fr):
        k = len(fr) // n
        return [[(t - c[0][0], i, l) for t, i, l in c] for c in (fr[j*k:(j+1)*k] for j in range(n))]
    return [{"normal": nm, "traffic": tr, "raw_bytes": len(tr) * LINE_BYTES, "name": f"Car {j+1}"}
            for j, (nm, tr) in enumerate(zip(chunks(normal), chunks(attack)))]

# ---------- on-car detection ----------
def learn_baseline(frames):
    dur = (frames[-1][0] - frames[0][0]) or 1
    return {i: c / dur for i, c in Counter(f[1] for f in frames).items()}

def detect(traffic, base):
    wins, lab = defaultdict(Counter), defaultdict(int)
    for t, i, l in traffic:
        w = int(t // WIN); wins[w][i] += 1; lab[w] |= l
    flagged, hits = {}, Counter()
    for w, c in wins.items():
        for i, n in c.items():
            b = base.get(i)
            if (b is None and n >= 20) or (b is not None and n / WIN > 3 * b):
                flagged.setdefault(w, []).append(i); hits[i] += 1
    tp = sum(1 for w in wins if lab[w] and w in flagged); fn = sum(1 for w in wins if lab[w] and w not in flagged)
    fp = sum(1 for w in wins if not lab[w] and w in flagged); tn = sum(1 for w in wins if not lab[w] and w not in flagged)
    atk_t = [t for t, _, l in traffic if l]
    delay = None
    hit_w = [w for w in flagged if lab[w]]
    if atk_t and hit_w: delay = max(0.0, (min(hit_w) + 1) * WIN - min(atk_t))
    return {"tpr": tp / (tp + fn) if tp + fn else None, "fpr": fp / (fp + tn) if fp + tn else None,
            "delay": delay, "top": hits.most_common(1)[0][0] if hits else None,
            "windows": (min(flagged), max(flagged)) if flagged else None, "n": sum(hits.values())}

def draft_rule(det, base):
    if det["top"] is None: return None
    known = det["top"] in base
    w0, w1 = det["windows"]
    return {"threat": "SPOOFING" if known else "CAN_FLOOD", "target_id": f"0x{det['top']:03X}",
            "action": "RATE_LIMIT" if known else "BLOCK",
            "window_start": round(w0 * WIN, 1), "window_end": round((w1 + 1) * WIN, 1), "frame_count": det["n"]}

def validate(draft):
    clean = {k: draft[k] for k in ("threat", "target_id", "action") if k in draft}
    stripped = [k for k in draft if k not in clean]
    ok = clean.get("threat") in THREATS and clean.get("action") in ACTIONS and ID_RE.match(str(clean.get("target_id", "")))
    return (clean if ok else None), stripped

# ---------- on-receiving-car enforcement ----------
def enforce(frames, rule, base):
    tid, kept, last = int(rule["target_id"], 16), [], -1e9
    minint = 0.8 / base[tid] if rule["action"] == "RATE_LIMIT" and tid in base else None
    for f in frames:
        if f[1] == tid:
            if rule["action"] == "BLOCK": continue
            if minint:
                if f[0] - last < minint: continue
                last = f[0]
        kept.append(f)
    return kept

def drop_stats(frames, kept):
    k = set(map(id, kept)); legit = [f for f in frames if not f[2]]; atk = [f for f in frames if f[2]]
    ld = sum(1 for f in legit if id(f) not in k); ad = sum(1 for f in atk if id(f) not in k)
    return {"legit_dropped": ld / len(legit) if legit else 0.0, "attack_dropped": ad / len(atk) if atk else None}

# ---------- whole fleet run ----------
def run_fleet(fleet, need=3, max_collateral=0.001):
    res = {"reports": [], "events": []}
    for v in fleet[:need]:
        base = learn_baseline(v["normal"]); det = detect(v["traffic"], base); d = draft_rule(det, base)
        if d is None: res["events"].append((v["name"], "no anomaly found")); continue
        clean, stripped = validate(d)
        res["reports"].append({"car": v["name"], "det": det, "draft": d, "clean": clean, "stripped": stripped,
                               "rule_bytes": len(json.dumps(clean, separators=(",", ":")).encode()) if clean else 0,
                               "raw_bytes": v["raw_bytes"]})
    keys = Counter((r["clean"]["threat"], r["clean"]["target_id"], r["clean"]["action"]) for r in res["reports"] if r["clean"])
    res["quorum"] = bool(keys) and keys.most_common(1)[0][1] >= need
    if not res["quorum"]: return res
    rule = dict(zip(("threat", "target_id", "action"), keys.most_common(1)[0][0]))
    if rule["target_id"] in SAFETY_CRITICAL and rule["action"] == "BLOCK": rule["action"] = "RATE_LIMIT"
    res["rule"] = rule; res["peer"], res["protect"] = [], []
    for v in fleet[need:]:
        base = learn_baseline(v["normal"])
        col = drop_stats(v["normal"], enforce(v["normal"], rule, base))["legit_dropped"]
        res["peer"].append({"car": v["name"], "collateral": col, "pass": col <= max_collateral})
    res["deployed"] = bool(res["peer"]) and all(p["pass"] for p in res["peer"])
    if res["deployed"]:
        for v in fleet[need:]:
            base = learn_baseline(v["normal"])
            res["protect"].append(dict(drop_stats(v["traffic"], enforce(v["traffic"], rule, base)), car=v["name"]))
    return res
