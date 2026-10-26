"""Everything that happens on the car: the (simulated) attack log and the AI extraction step."""
import json
import os
import random
import re

NORMAL_IDS = ["0x244", "0x3F0", "0x0B0", "0x2C0"]


def make_log(car_id, target="0x1A2", n=60):
    """Fake CAN log for a flood attack. Every line carries private data (GPS, speed, VIN)."""
    vin = f"5YJ3E1EA{car_id}KF{random.randint(100000, 999999)}"
    lat, lon = 12.97 + random.random() / 50, 77.59 + random.random() / 50
    lines = []
    for t in range(n):
        cid = target if random.random() < 0.65 else random.choice(NORMAL_IDS)
        data = "".join(random.choice("0123456789ABCDEF") for _ in range(16))
        lines.append(
            f"t=17{t:05d} id={cid} data={data} gps=({lat + t * 1e-4:.5f},{lon:.5f}) "
            f"speed={random.randint(30, 90)}kmh vin={vin}"
        )
    return lines


VIRUS_PROFILES = {
    "CAN-Worm.Apex": {
        "threat": "MALWARE_VIRUS",
        "target_id": "0x1A2",
        "desc": "Infiltrates vehicle gateway to inject high-frequency malicious packets",
    },
    "GhostBrake.Trojan": {
        "threat": "TROJAN_INJECT",
        "target_id": "0x1E4",
        "desc": "Trojan horse targeting brake assist communication frames",
    },
    "BatteryDrainer.ZeroDay": {
        "threat": "MALWARE_VIRUS",
        "target_id": "0x3D1",
        "desc": "Zero-day payload hijacking battery management compute",
    },
}


def make_virus_dump(car_id, virus_name="CAN-Worm.Apex"):
    """Simulates a virus infection dump on the car, containing virus telemetry mixed with private driver data."""
    profile = VIRUS_PROFILES.get(virus_name, VIRUS_PROFILES["CAN-Worm.Apex"])
    vin = f"5YJ3E1EA{car_id}KF{random.randint(100000, 999999)}"
    lat, lon = 12.9716 + random.random() / 50, 77.5946 + random.random() / 50
    return {
        "virus_name": virus_name,
        "threat": profile["threat"],
        "target_id": profile["target_id"],
        "behavior": profile["desc"],
        # Sensitive vehicle telematics that must be removed by AI:
        "gps": f"({lat:.5f}, {lon:.5f})",
        "speed": f"{random.randint(35, 80)} km/h",
        "vin": vin,
        "driver_route": "Private Residence -> Downtown Office",
    }


def ai_sanitize_and_synthesize_antibody(virus_dump):
    """The AI agent analyzes the virus, scrubs all private data (GPS, VIN, speed), and synthesizes an antibody rule."""
    sensitive_keys = [k for k in ("gps", "speed", "vin", "driver_route") if k in virus_dump]
    
    # AI isolates the virus mechanism
    clean_virus_info = {
        "virus_name": virus_dump["virus_name"],
        "threat": virus_dump["threat"],
        "target_id": virus_dump["target_id"],
        "behavior": virus_dump["behavior"],
    }
    
    # AI synthesizes the antibody rule
    antibody = {
        "threat": virus_dump["threat"],
        "target_id": virus_dump["target_id"],
        "action": "BLOCK",
    }
    return clean_virus_info, sensitive_keys, antibody



def redact_log(lines):
    """Strip each line down to id, data and relative frame index so the model never sees GPS, speed or VIN."""
    redacted = []
    for idx, ln in enumerate(lines):
        m = re.search(r"id=(0x[0-9A-Fa-f]+).*?data=([0-9A-Fa-f]+)", ln)
        if m:
            redacted.append(f"frame={idx:03d} id={m.group(1)} data={m.group(2)}")
    return redacted


def heuristic_extract(lines, misbehave=False):
    """Local stand-in for the AI: finds the dominant message ID in the log."""
    counts = {}
    for ln in lines:
        m = re.search(r"id=(0x[0-9A-Fa-f]+)", ln)
        if m:
            counts[m.group(1)] = counts.get(m.group(1), 0) + 1
    top, c = max(counts.items(), key=lambda kv: kv[1])
    draft = {
        "threat": "CAN_FLOOD" if c / len(lines) > 0.4 else "SPOOFING",
        "target_id": top,
        "action": "BLOCK",
    }
    if misbehave:  # simulate a model leaking private fields
        draft.update({"gps": "(12.9716,77.5946)", "vin": "5YJ3E1EA1KF123456", "timestamp": "17:42:09"})
    return draft


def llm_extract(lines):
    """Real model call to Gemini. Needs `pip install google-genai` and GEMINI_API_KEY."""
    from google import genai
    from google.genai import types

    clean = redact_log(lines)
    key = os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")
    client = genai.Client(api_key=key) if key else genai.Client()
    prompt = (
        "You are an in-vehicle intrusion analyst. Read this CAN log and reply with ONLY a JSON object "
        'with keys threat (CAN_FLOOD|SPOOFING|REPLAY), target_id (e.g. "0x1A2"), '
        "action (BLOCK|ALERT|RATE_LIMIT).\n\n" + "\n".join(clean[:60])
    )
    resp = client.models.generate_content(
        model=os.environ.get("GEMINI_MODEL", "gemini-3.5-flash"),
        contents=prompt,
        config=types.GenerateContentConfig(response_mime_type="application/json", temperature=0),
    )
    return json.loads(re.sub(r"```json|```", "", resp.text).strip())

