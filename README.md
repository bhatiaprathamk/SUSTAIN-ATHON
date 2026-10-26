# 🛡️ ImmuneFleet

**Cars share antibodies, not data.**

When one electric car is hacked (for example, a flood on the CAN bus that disrupts the brakes), other cars of the same model are probably vulnerable too. They should warn each other, but the evidence is the raw log, which holds GPS, speed, driving habits and the VIN. Sharing that is a privacy problem.

ImmuneFleet works like an immune system. A car never shares data. It shares a tiny rule describing how to block the attack:

```json
{"threat": "CAN_FLOOD", "target_id": "0x1A2", "action": "BLOCK"}
```

The rule format has no field for location, speed, VIN or time.

## How it works

1. **Redact & Extract (on the car):** logs are redacted to strip GPS, speed, and VIN down to a relative frame index, message ID, and payload data *before* the AI sees them (**Privacy Layer 1**). A small AI model then reads the clean frames and drafts a rule.
2. **Validate (privacy guard):** a strict allowlist (`validator.py`) strips any extra or hallucinated fields and rejects invalid rules (**Privacy Layer 2**). Privacy depends on short, checkable deterministic code, not on the AI behaving.
3. **Sign and send:** the car signs the rule with its own device key.
4. **Fast response (1 report):** the reporting car applies its own rule instantly (it is its own car, so no trust is needed). The cloud also shares an **ALERT-only** version with the fleet, so other cars get a warning within seconds. A single report can never cause a hard BLOCK, and never reaches safety-critical IDs (braking, steering). If nobody corroborates it, it is withdrawn.
5. **Consensus (3 reports):** a hard rule needs **3 distinct signed cars** reporting the same `threat + target_id`. Rules stuck below 3 expire and are deleted.
6. **Peer testing, then staged rollout:** healthy cars test the rule in a sandbox against normal driving and hard-braking scenarios. A rule that would break normal behavior fails and is deleted. A BLOCK on a safety-critical ID is downgraded to RATE_LIMIT. A passing rule is signed by the cloud and rolled out in stages. Every car verifies the signature before applying it.

## Run it

```bash
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
python3 -m pip install -r requirements.txt
streamlit run app.py
```

Optional, to use a real LLM (Google Gemini, free tier) for the AI step. Get a key from Google AI Studio:

```bash
export GEMINI_API_KEY="your-key"
```

Then tick **Use real LLM for the AI step** in the sidebar. Without a key, a local extractor is used.

## Demo script

- **Play full demo:** the sidebar button runs the whole happy path automatically (tick *Make the AI misbehave* first to show the validator at work).
- **Happy path (manual):** attack Car 1, 2, 3 (Pending 1/3 → 3/3 → antibody deployed), then attack Car 4 and 5 (blocked, immune).
- **Fast response:** attack Car 1 only. It is contained at once by its own rule and the rest of the fleet gets an alert-only warning. The sidebar switch turns this off to show the original 3-car-only behavior.
- **Poison:** one hacked car sends a fake rule. It can only trigger alerts (nothing on safety-critical IDs) and sticks at 1/3, then expires (*Let time pass*).
- **Bad rule:** 3 cars report a rule that would block emergency braking. It reaches consensus but fails peer testing and is deleted.
- **Misbehaving AI:** tick *Make the AI misbehave*, attack a car, and watch the validator strip the GPS, VIN and timestamp.

Cars whose rule fails or expires recover to healthy on their own. The rollout is shown stage by stage on the cars. Press **Reset demo** any time to start clean.

## Code map

| File | Role |
|---|---|
| `app.py` | Streamlit UI only |
| `car.py` | Fake attack log, local and real-LLM rule extraction |
| `validator.py` | The privacy allowlist |
| `cloud.py` | Signature check, 3-car consensus, peer test, deployment |
| `signing.py` | Signing helpers |

## Honest limitations

- The attacks and the AI step are simulated in the demo (the AI step can be a real LLM call).
- The cloud is Python code in the same process, not a separate service.
- Peer testing uses a small rule table, not a replay of real driving data.
- The first car is hit before any defense exists. Its own local antibody contains it at once, but it is still the fleet's first responder, which is an inherent tradeoff of collective defense. Hard fleet-wide blocking waits for 3 reports.
- A fake single-car rule can still cause harmless alerts on non-safety IDs until it expires. Alert-only mode bounds the harm instead of removing it.
- Hardware-backed signing is described, not built (HMAC stands in for device keys).
- An attacker who controls 3 real cars could still fool consensus. Requiring diversity (different regions or firmware versions) is future work.
