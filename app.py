"""ImmuneFleet demo UI (Streamlit). Logic lives in car.py, validator.py, cloud.py, signing.py."""
import json
import os
import time

import streamlit as st

from car import heuristic_extract, llm_extract, make_log
from cloud import REQUIRED, Cloud
from signing import CLOUD_KEY, car_key, sign
from validator import validate

st.set_page_config(page_title="ImmuneFleet", page_icon="🛡️", layout="wide")

N_CARS = 5
ATTACK_TARGET = "0x1A2"
STAGE_SIZES = [1, 3, N_CARS]  # canary cars, then half the fleet, then everyone
STEP_DELAY = 1.2


# ---------------------------------------------------------------- state
def on_deploy(rule, sig):
    """Start a staged rollout: healthy cars get the update first, compromised ones last."""
    order = sorted(S.cars, key=lambda i: S.cars[i]["status"] in ("compromised", "contained"))
    S.rollout = {"rule": rule, "sig": sig, "stage": 0, "order": order}
    st.toast("CONSENSUS REACHED: ANTIBODY DEPLOYED", icon="✅")


def on_release(car_ids):
    """A rule failed or expired, so the cars that reported it are cleaned up."""
    for i in car_ids:
        S.cars[i].update(status="healthy", note="Recovered: rule was discarded")


def on_provisional(rule, sig):
    """Healthy cars get an ALERT-only antibody. It can warn but never block."""
    for c in S.cars.values():
        if c["status"] == "healthy":
            c.update(status="alert", note="Provisional ALERT-only antibody")
    st.toast("Provisional alert-only antibody shared with the fleet", icon="🟡")


def on_provisional_end():
    for c in S.cars.values():
        if c["status"] == "alert":
            c.update(status="healthy", note="Provisional antibody withdrawn")


def apply_rollout_stage():
    """Each car in the current stage verifies the cloud signature, then applies the antibody."""
    ro = S.rollout
    for i in ro["order"][: STAGE_SIZES[ro["stage"]]]:
        assert ro["sig"] == sign(CLOUD_KEY, ro["rule"])
        S.cars[i].update(status="immune", note="Antibody applied (signature verified)")
    for i in ro["order"][STAGE_SIZES[ro["stage"]]:]:
        if S.cars[i]["status"] in ("healthy", "alert"):
            S.cars[i]["note"] = f"Waiting for update (stage {ro['stage'] + 1}/{len(STAGE_SIZES)})"


def init_state():
    st.session_state.cars = {
        i: {"status": "healthy", "note": "", "raw": None, "draft": None, "rule": None, "stripped": []}
        for i in range(1, N_CARS + 1)
    }
    st.session_state.cloud = Cloud(on_deploy=on_deploy, on_release=on_release,
                                    on_provisional=on_provisional, on_provisional_end=on_provisional_end)
    st.session_state.last_car = None
    st.session_state.rollout = None
    st.session_state.demo_step = None  # None = not playing


if "cars" not in st.session_state:
    init_state()
S = st.session_state


# ---------------------------------------------------------------- callbacks
def send(car_id, rule):
    S.cloud.fast_response = S.get("fast_response", True)
    S.cloud.receive(car_id, rule, sign(car_key(car_id), rule))


def attack(car_id):
    c, cloud = S.cars[car_id], S.cloud
    S.last_car = car_id
    if c["status"] in ("compromised", "contained"):
        return
    if c["status"] == "alert":
        cloud.log(f"🟡 Car {car_id}: provisional antibody raised an ALERT (attack not blocked)")
    if cloud.has_antibody_for(ATTACK_TARGET) and c["status"] in ("immune", "blocked"):
        c["status"], c["note"] = "blocked", "ATTACK BLOCKED - IMMUNE"
        cloud.log(f"🔵 Car {car_id}: attack blocked instantly by the deployed antibody")
        return
    lines = make_log(car_id)
    try:
        draft = llm_extract(lines) if S.get("use_llm") else heuristic_extract(lines, S.get("misbehave", False))
    except Exception as e:  # never let the demo die on stage
        cloud.log(f"⚠️ LLM call failed ({type(e).__name__}: {str(e)[:80]}); using local extractor")
        draft = heuristic_extract(lines, S.get("misbehave", False))
    rule, stripped, reason = validate(draft)
    c.update(status="compromised", note="Under attack", raw=lines, draft=draft, rule=rule, stripped=stripped)
    cloud.log(f"🔴 Car {car_id} attacked; AI drafted {json.dumps(draft)}")
    if stripped:
        cloud.log(f"🛡️ Validator stripped private fields from Car {car_id}: {', '.join(stripped)}")
    if rule is None:
        cloud.log(f"🛡️ Validator REJECTED Car {car_id}'s rule: {reason}")
        return
    if S.get("fast_response", True):
        c.update(status="contained", note="Local antibody applied instantly")
        cloud.log(f"🟠 Car {car_id}: attack contained by its own local antibody")
    send(car_id, rule)


def healthy_cars():
    return [i for i, c in S.cars.items() if c["status"] == "healthy"]


def poison():
    healthy = healthy_cars()
    if not healthy:
        st.toast("No healthy car left to compromise. Reset first.")
        return
    i = healthy[-1]
    S.cars[i].update(status="compromised", note="Hacked: sending a fake rule", rule=None, raw=None, draft=None, stripped=[])
    fake = {"threat": "CAN_FLOOD", "target_id": "0x0B0", "action": "BLOCK"}
    S.cloud.log(f"☠️ Car {i} is hacked and sends a fake rule (BLOCK brakes)")
    send(i, fake)


def bad_rule():
    healthy = healthy_cars()[:REQUIRED]
    if len(healthy) < REQUIRED:
        st.toast("Need 3 healthy cars. Reset first.")
        return
    bad = {"threat": "SPOOFING", "target_id": "0x0B0", "action": "BLOCK"}
    S.cloud.log("⚠️ 3 cars report a rule that would block emergency braking")
    for i in healthy:
        S.cars[i].update(status="compromised", note="Reported a bad rule")
        send(i, bad)


def expire():
    if not S.cloud.expire_stuck():
        st.toast("Nothing pending to expire.")


def start_demo():
    init_state()
    S.demo_step = 0


# ---------------------------------------------------------------- UI
st.title("🛡️ ImmuneFleet")
st.caption("Cars share antibodies, not data. A tiny validated rule leaves the car; the raw log never does.")

with st.sidebar:
    st.header("Demo settings")
    st.checkbox("Use real LLM for the AI step", key="use_llm", help="Needs the google-genai package and GEMINI_API_KEY.")
    if S.get("use_llm") and not (os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")):
        st.warning("GEMINI_API_KEY is not set; the demo will fall back to the local extractor.")
    st.checkbox("Fast response: 1 report makes a provisional alert-only antibody", key="fast_response", value=True,
                help="Off = the original behavior: nothing happens fleet-wide until 3 cars report.")
    st.checkbox("Make the AI misbehave (leak GPS/VIN)", key="misbehave", help="Shows the validator stripping private fields.")
    st.divider()
    st.button("▶️ Play full demo", on_click=start_demo, use_container_width=True,
              help="Runs the happy path automatically: attack Cars 1 to 5.")
    st.button("🔁 Reset demo", on_click=init_state, use_container_width=True)

if S.rollout:
    apply_rollout_stage()

COLORS = {"contained": "#e08a00", "alert": "#c9a400", "healthy": "#1f9d55", "compromised": "#d64545", "immune": "#2b7de9", "blocked": "#2b7de9"}
LABEL = {"contained": "ATTACK CONTAINED", "alert": "ALERT-ONLY ANTIBODY", "healthy": "HEALTHY", "compromised": "COMPROMISED", "immune": "IMMUNE", "blocked": "ATTACK BLOCKED - IMMUNE"}

for i, col in zip(S.cars, st.columns(N_CARS)):
    c = S.cars[i]
    col.markdown(
        f"<div style='border:2px solid {COLORS[c['status']]};border-radius:12px;padding:12px;text-align:center'>"
        f"<div style='font-size:34px'>🚗</div><b>Car {i}</b><br>"
        f"<span style='color:{COLORS[c['status']]};font-weight:700'>{LABEL[c['status']]}</span><br>"
        f"<span style='font-size:12px;opacity:.7'>{c['note'] or '&nbsp;'}</span></div>",
        unsafe_allow_html=True,
    )
    col.button(f"Attack Car {i}", key=f"atk{i}", on_click=attack, args=(i,), use_container_width=True)

st.write("")
b1, b2, b3 = st.columns(3)
b1.button("☠️ Poison: one car sends a fake rule", on_click=poison, use_container_width=True)
b2.button("⚠️ Bad rule: blocks emergency braking", on_click=bad_rule, use_container_width=True)
b3.button("⌛ Let time pass (expire stuck rules)", on_click=expire, use_container_width=True)

left, right = st.columns([3, 2])

with left:
    st.subheader("Raw log vs. what is sent")
    cid = S.last_car if S.last_car and S.cars[S.last_car]["raw"] else next(
        (i for i, c in S.cars.items() if c["raw"]), None
    )
    if cid is None:
        st.info("Attack a car to see the raw log and the tiny rule that leaves it.")
    else:
        c = S.cars[cid]
        rl, rr = st.columns(2)
        with rl:
            st.markdown(f"**Car {cid}: raw log (stays on the car)**")
            st.code("\n".join(c["raw"][:12]) + "\n...", language="text")
            st.caption("Contains GPS, speed and VIN on every line.")
        with rr:
            st.markdown("**AI draft → validator → sent**")
            st.caption("AI draft")
            st.json(c["draft"])
            if c["stripped"]:
                st.error("Stripped by validator: " + ", ".join(c["stripped"]))
            if c["rule"]:
                st.caption("Sent to the cloud (signed)")
                st.json(c["rule"])
            else:
                st.error("Rule rejected by validator. Nothing was sent.")

with right:
    st.subheader("☁️ Cloud")
    cloud = S.cloud
    if not cloud.pending and not cloud.deployed:
        st.write("No rules yet.")
    for k, e in cloud.pending.items():
        n = len(e["reports"])
        st.markdown(f"**Pending `{k}`**: {n}/{REQUIRED}")
        st.progress(n / REQUIRED)
    for k, d in cloud.provisional.items():
        st.warning(f"PROVISIONAL `{k}` → ALERT only, until {REQUIRED} cars corroborate")
    for k, d in cloud.deployed.items():
        st.success(f"DEPLOYED `{k}` → {d['rule']['action']}  (cloud sig `{d['sig']}`)")
    if cloud.last_test:
        t = cloud.last_test
        (st.success if t["verdict"] == "PASS" else st.warning if t["verdict"] == "DOWNGRADE" else st.error)(
            f"Peer test {t['key']}: **{t['verdict']}**. {t['why']}"
        )

st.subheader("Event log")
for e in S.cloud.events[:15]:
    st.write(e)


# ---------------------------------------------------------------- driver (rollout stages and auto-play)
if S.rollout:
    time.sleep(STEP_DELAY)
    S.cloud.log(f"🚦 Rollout stage {S.rollout['stage'] + 1}/{len(STAGE_SIZES)} complete")
    if S.rollout["stage"] + 1 < len(STAGE_SIZES):
        S.rollout["stage"] += 1
    else:
        S.rollout = None
    st.rerun()
elif S.demo_step is not None:
    time.sleep(STEP_DELAY)
    if S.demo_step < N_CARS:
        attack(S.demo_step + 1)
        S.demo_step += 1
    else:
        S.demo_step = None
    st.rerun()
