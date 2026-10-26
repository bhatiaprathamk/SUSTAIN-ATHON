"""The privacy guard. A fixed allowlist sits between the AI and the network.

Privacy does not depend on the AI behaving: anything outside the schema is
stripped, and a rule with an invalid field is rejected outright.
"""
import re

THREATS = {"CAN_FLOOD", "SPOOFING", "REPLAY", "MALWARE_VIRUS", "TROJAN_INJECT"}
ACTIONS = {"BLOCK", "ALERT", "RATE_LIMIT"}
ALLOWED_KEYS = {"threat", "target_id", "action"}
ID_RE = re.compile(r"^0x[0-9A-Fa-f]{1,3}$")


def validate(draft):
    """Return (clean_rule or None, stripped_keys, reject_reason)."""
    if not isinstance(draft, dict):
        return None, [], "not an object"
    stripped = [k for k in draft if k not in ALLOWED_KEYS]
    tid = str(draft.get("target_id", ""))
    if draft.get("threat") not in THREATS:
        return None, stripped, "threat not on allowlist"
    if draft.get("action") not in ACTIONS:
        return None, stripped, "action not on allowlist"
    if not ID_RE.match(tid):
        return None, stripped, "target_id is not a valid message ID"
    clean = {
        "threat": draft["threat"],
        "target_id": "0x" + tid[2:].upper(),
        "action": draft["action"],
    }
    return clean, stripped, ""
