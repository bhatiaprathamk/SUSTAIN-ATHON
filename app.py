"""ImmuneFleet demo UI (Streamlit). Logic lives in car.py, validator.py, cloud.py, signing.py."""
import json
import os
import re
import time

import streamlit as st

from car import (
    VIRUS_PROFILES,
    ai_sanitize_and_synthesize_antibody,
    heuristic_extract,
    llm_extract,
    make_log,
    make_virus_dump,
    redact_log,
)
from cloud import REQUIRED, Cloud
from signing import CLOUD_KEY, car_key, sign
from validator import validate

st.set_page_config(page_title="ImmuneFleet", page_icon="🛡️", layout="wide")

N_CARS = 5
ATTACK_TARGET = "0x1A2"
STAGE_SIZES = [1, 3, N_CARS]  # canary cars, then half the fleet, then everyone
STEP_DELAY = 1.2


def format_raw_log_lines(raw_lines, max_lines=8):
    """Parses raw CAN log strings into clean, structured dictionaries for tabular presentation."""
    parsed = []
    for idx, ln in enumerate(raw_lines[:max_lines]):
        m_id = re.search(r"id=(0x[0-9A-Fa-f]+)", ln)
        m_data = re.search(r"data=([0-9A-Fa-f]+)", ln)
        m_gps = re.search(r"gps=(\([^)]+\))", ln)
        m_spd = re.search(r"speed=([0-9]+kmh)", ln)
        m_vin = re.search(r"vin=([0-9A-Za-z]+)", ln)
        parsed.append({
            "Frame": f"#{idx:02d}",
            "CAN ID": m_id.group(1) if m_id else "N/A",
            "Payload Data": m_data.group(1) if m_data else "N/A",
            "📍 GPS (Private)": m_gps.group(1) if m_gps else "N/A",
            "⚡ Speed (Private)": m_spd.group(1) if m_spd else "N/A",
            "🏷️ VIN (Private)": m_vin.group(1) if m_vin else "N/A",
        })
    return parsed


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
        i: {"status": "healthy", "note": "", "raw": None, "redacted": None, "draft": None, "rule": None, "stripped": []}
        for i in range(1, N_CARS + 1)
    }
    st.session_state.cloud = Cloud(on_deploy=on_deploy, on_release=on_release,
                                    on_provisional=on_provisional, on_provisional_end=on_provisional_end)
    st.session_state.last_car = None
    st.session_state.rollout = None
    st.session_state.demo_step = None  # None = not playing
    st.session_state.virus_event = None


if "cars" not in st.session_state:
    init_state()
S = st.session_state


# ---------------------------------------------------------------- callbacks
def send(car_id, rule):
    S.cloud.fast_response = S.get("fast_response", False)
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
    redacted = redact_log(lines)
    try:
        draft = llm_extract(redacted) if S.get("use_llm") else heuristic_extract(redacted, S.get("misbehave", False))
    except Exception as e:  # never let the demo die on stage
        cloud.log(f"⚠️ LLM call failed ({type(e).__name__}: {str(e)[:80]}); using local extractor")
        draft = heuristic_extract(redacted, S.get("misbehave", False))
    rule, stripped, reason = validate(draft)
    c.update(status="compromised", note="Under attack", raw=lines, redacted=redacted, draft=draft, rule=rule, stripped=stripped)
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


def inject_virus(car_id, virus_name):
    c, cloud = S.cars[car_id], S.cloud
    S.last_car = car_id
    target_id = VIRUS_PROFILES[virus_name]["target_id"]

    # Check if this car is already immunized against this virus
    if cloud.has_antibody_for(target_id) and c["status"] in ("immune", "blocked"):
        c["status"], c["note"] = "blocked", f"VIRUS BLOCKED — IMMUNE ({virus_name})"
        cloud.log(f"🛡️ Car {car_id}: {virus_name} blocked on arrival! Protected by fleet vaccine.")
        st.toast(f"Car {car_id} is immune to {virus_name}!", icon="🛡️")
        return

    # 1. Virus enters car and triggers error/telemetry dump
    raw_dump = make_virus_dump(car_id, virus_name)
    c.update(status="compromised", note=f"Infected by {virus_name}")
    cloud.log(f"🦠 Car {car_id} infected by virus '{virus_name}' targeting CAN ID {target_id}")

    # 2. AI agent on the car cleans private telematics (GPS, speed, VIN, route)
    clean_info, sensitive_purged, antibody_draft = ai_sanitize_and_synthesize_antibody(raw_dump)
    cloud.log(f"🤖 AI Agent on Car {car_id} stripped private telematics: {', '.join(sensitive_purged)}")

    # 3. Privacy validator allowlist guarantees clean rule
    rule, stripped, reason = validate(antibody_draft)

    # 4. Generate simulated CAN bus log for vehicle display
    lines = make_log(car_id, target=target_id)
    redacted = redact_log(lines)
    c.update(raw=lines, redacted=redacted, draft=antibody_draft, rule=rule, stripped=stripped + sensitive_purged)

    # 5. Save event details for UI visualization
    S.virus_event = {
        "car_id": car_id,
        "virus_name": virus_name,
        "raw_dump": raw_dump,
        "clean_info": clean_info,
        "purged": sensitive_purged,
        "antibody": rule,
    }

    # 6. Car applies local defense instantly
    c.update(status="contained", note="Virus contained by local antibody")
    cloud.log(f"🟠 Car {car_id}: local antibody applied to neutralize {virus_name}")

    # 7. Cloud signs and deploys vaccine across all other EV cars
    cloud.deploy_vaccine(rule)


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
st.caption("Cars share antibodies, not data. A tiny validated micro-rule leaves the car; the raw log never does.")

# Metric KPIs
m1, m2, m3, m4 = st.columns(4)
m1.metric("Connected Fleet", f"{N_CARS} EVs")
m2.metric("Telemetry Privacy", "100% Onboard", delta="Zero PII Egress")
m3.metric("Consensus Threshold", f"{REQUIRED} Distinct Cars")
m4.metric("Active Antibodies", f"{len(S.cloud.deployed)} Deployed")

with st.sidebar:
    st.header("Demo settings")
    st.checkbox("Use real LLM for the AI step", key="use_llm", help="Needs the google-genai package and GEMINI_API_KEY.")
    if S.get("use_llm") and not (os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")):
        st.warning("GEMINI_API_KEY is not set; the demo will fall back to the local extractor.")
    st.checkbox("Fast response: 1 report makes a provisional alert-only antibody", key="fast_response", value=False,
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
b1, b2, b3, b4 = st.columns(4)
b1.button("☠️ Poison: fake rule", on_click=poison, use_container_width=True)
b2.button("⚠️ Bad rule: brake block", on_click=bad_rule, use_container_width=True)
b3.button("⌛ Let time pass (expire)", on_click=expire, use_container_width=True)
b4.button("🔁 Reset demo", on_click=init_state, use_container_width=True)

st.write("")
left, right = st.columns([1.5, 1.0])

with left:
    cid = S.last_car if S.last_car and S.cars[S.last_car]["raw"] else next(
        (i for i, c in S.cars.items() if c["raw"]), None
    )
    st.subheader(f"🔍 Vehicle Privacy Pipeline {'(Car ' + str(cid) + ')' if cid else ''}")
    if cid is None:
        st.info("👆 Click **'Attack Car 1'** above to trigger an attack and inspect the 3-layer privacy pipeline.")
    else:
        c = S.cars[cid]
        tab_raw, tab_layer1, tab_layer2 = st.tabs([
            "🔴 1. Raw Telemetry (Exposes PII)",
            "🔒 2. Privacy Layer 1 (Redacted for AI)",
            "🛡️ 3. Privacy Layer 2 (Validator & Sent Rule)"
        ])
        
        with tab_raw:
            st.error("🚨 SENSITIVE DATA EXPOSURE: This raw CAN log resides on the vehicle's ECU. Every frame exposes exact GPS coordinates, speed, and VIN. Sharing this with third parties or the cloud violates driver privacy.")
            raw_table = format_raw_log_lines(c["raw"], max_lines=8)
            st.dataframe(raw_table, use_container_width=True, hide_index=True)
            st.caption(f"Showing 8 of {len(c['raw'])} captured CAN frames. Stored strictly on Car {cid}; never transmitted.")

        with tab_layer1:
            st.info("🔒 PRE-INFERENCE REDACTION: Before passing data to the onboard AI model, each line is stripped down strictly to its relative frame index, CAN ID, and data payload. The model prompt never contains GPS, speed, or VIN.")
            if c.get("redacted"):
                st.code("\n".join(c["redacted"][:8]) + "\n...", language="text")
            st.success("✅ Context Window Scrubbed: 0 GPS coordinates | 0 Speed values | 0 VIN numbers")

        with tab_layer2:
            st.success("🛡️ DETERMINISTIC SCHEMA VALIDATION: Privacy does not rely on the AI behaving. A hardcoded allowlist checks the output. Any unknown or leaked fields are stripped, and invalid rules are dropped.")
            c1, c2 = st.columns(2)
            with c1:
                st.markdown("**AI Draft Output:**")
                st.json(c["draft"])
                if c["stripped"]:
                    st.error(f"🚨 Stripped by validator: {', '.join(c['stripped'])}")
            with c2:
                st.markdown("**Final Transmitted Rule (Signed):**")
                if c["rule"]:
                    st.json(c["rule"])
                    st.caption(f"🔏 Cryptographic Signature: `HMAC-SHA256 (car-{cid}-device-secret)`")
                else:
                    st.error("Rule rejected by validator. Nothing was sent.")

with right:
    st.subheader("☁️ Cloud Defense & Consensus")
    cloud = S.cloud
    
    # 1. Consensus Tracker
    st.markdown("##### 🤝 Fleet Consensus Tracker")
    if not cloud.pending and not cloud.deployed:
        st.info("No active attack reports. Waiting for vehicle reports.")
    for k, e in cloud.pending.items():
        n = len(e["reports"])
        st.markdown(f"**Target:** `{k}` — **{n}/{REQUIRED} Cars Corroborated**")
        st.progress(n / REQUIRED)
        st.caption(f"Signatures from: {', '.join(['Car ' + str(r_cid) for r_cid in e['reports']])}")
        
    for k, d in cloud.provisional.items():
        st.warning(f"🟡 PROVISIONAL `{k}`: ALERT-only warning active.")
        
    # 2. Peer Testing Sandbox
    st.markdown("##### 🧪 Peer Testing Sandbox")
    if cloud.last_test:
        t = cloud.last_test
        if t["verdict"] == "PASS":
            st.success(f"**Peer Test Result:** `{t['key']}` ➔ **PASS**\n\n{t['why']}")
        elif t["verdict"] == "DOWNGRADE":
            st.warning(f"**Peer Test Result:** `{t['key']}` ➔ **DOWNGRADE**\n\n{t['why']}")
        else:
            st.error(f"**Peer Test Result:** `{t['key']}` ➔ **FAIL**\n\n{t['why']}")
    else:
        st.caption("Sandbox automatically tests rules against emergency braking and driving replays before rollout.")
        
    # 3. Deployed Antibodies
    st.markdown("##### 🛡️ Deployed Fleet Antibodies")
    if cloud.deployed:
        for k, d in cloud.deployed.items():
            st.success(f"**Antibody `{k}` Active**\n- Action: `{d['rule']['action']}`\n- Cloud Sig: `{d['sig']}`")
    else:
        st.caption("No antibodies deployed yet.")

st.write("")
tab_virus, tab_events = st.tabs(["🦠 Zero-Day EV Virus & Fleet Vaccine Lab", "📜 Real-Time Fleet Event Log"])

with tab_virus:
    st.caption("Inject a zero-day virus into an EV. The onboard AI agent inspects the malware, strips all driver PII (GPS, speed, VIN), synthesizes an antibody, and immunizes the entire EV fleet.")
    vcol1, vcol2, vcol3 = st.columns([2.5, 1.2, 1.8])
    with vcol1:
        sel_virus = st.selectbox(
            "Select Virus Strain",
            list(VIRUS_PROFILES.keys()),
            key="virus_choice",
            format_func=lambda v: f"{v} (Target: {VIRUS_PROFILES[v]['target_id']})",
        )
        st.caption(f"**Behavior:** {VIRUS_PROFILES[sel_virus]['desc']}")
    with vcol2:
        target_car = st.selectbox("Target Car", list(S.cars.keys()), key="target_car_choice")
    with vcol3:
        st.write("")
        st.button(f"🦠 Inject {sel_virus} into Car {target_car}", on_click=inject_virus, args=(target_car, sel_virus), use_container_width=True)

    if S.get("virus_event"):
        ve = S.virus_event
        ec1, ec2, ec3 = st.columns(3)
        with ec1:
            st.markdown("**1. Raw Virus Telemetry Dump**")
            st.json(ve["raw_dump"])
            st.caption("Contains malware payload mixed with private GPS, speed, route, and VIN.")
        with ec2:
            st.markdown("**2. AI Agent Sanitization & Learning**")
            st.error("🚨 Stripped Sensitive Driver PII:\n- " + "\n- ".join(ve["purged"]))
            st.markdown("**Clean Virus Mechanism:**")
            st.json(ve["clean_info"])
        with ec3:
            st.markdown("**3. Synthesized Fleet Vaccine (Antibody)**")
            st.success("✅ Clean Signed Antibody:")
            st.json(ve["antibody"])
            st.caption("Signed by Cloud ➔ Broadcasted ➔ All other EV cars are now immune!")

with tab_events:
    for e in S.cloud.events[:20]:
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
