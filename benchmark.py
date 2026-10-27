"""Command line benchmark. Examples:
  python benchmark.py                     # synthetic DoS + injection
  python benchmark.py normal.txt attack.csv   # real files (e.g. an open CAN intrusion dataset)"""
import sys
from pipeline import *

def show(title, fleet):
    r = run_fleet(fleet); print(f"\n== {title} ==")
    for x in r["reports"]:
        print(f"{x['car']}: detect delay {x['det']['delay']}s, window TPR {x['det']['tpr']}, FPR {x['det']['fpr']}, "
              f"raw log {x['raw_bytes']:,} B -> rule {x['rule_bytes']} B, stripped {x['stripped']}")
    print("quorum:", r["quorum"], "| rule:", r.get("rule"), "| deployed:", r.get("deployed"))
    for p in r.get("peer", []): print(f"peer test {p['car']}: legit frames dropped {p['collateral']:.3%} -> {'PASS' if p['pass'] else 'FAIL'}")
    for p in r.get("protect", []): print(f"protection {p['car']}: attack frames dropped {p['attack_dropped']:.1%}, legit frames lost {p['legit_dropped']:.1%}")

if len(sys.argv) == 3:
    normal, attack = (parse_frames(open(p, errors="ignore").read()) for p in sys.argv[1:3])
    show("real data (sliced into 5 vehicles)", fleet_from_real(normal, attack))
else:
    show("synthetic DoS flood", synthetic_fleet("dos")); show("synthetic injection", synthetic_fleet("inject"))
