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

    client = genai.Client()  # reads GEMINI_API_KEY (or GOOGLE_API_KEY) from the environment
    prompt = (
        "You are an in-vehicle intrusion analyst. Read this CAN log and reply with ONLY a JSON object "
        'with keys threat (CAN_FLOOD|SPOOFING|REPLAY), target_id (e.g. "0x1A2"), '
        "action (BLOCK|ALERT|RATE_LIMIT).\n\n" + "\n".join(lines[:60])
    )
    resp = client.models.generate_content(
        model=os.environ.get("GEMINI_MODEL", "gemini-3.5-flash"),
        contents=prompt,
        config=types.GenerateContentConfig(response_mime_type="application/json", temperature=0),
    )
    return json.loads(re.sub(r"```json|```", "", resp.text).strip())
