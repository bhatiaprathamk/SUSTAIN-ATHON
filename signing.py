"""Signing helpers. HMAC stands in for hardware-backed device keys (described, not built)."""
import hashlib
import hmac
import json

CLOUD_KEY = b"cloud-demo-signing-key"


def car_key(car_id):
    return f"car-{car_id}-device-secret".encode()


def canon(rule):
    return json.dumps(rule, sort_keys=True, separators=(",", ":")).encode()


def sign(key, rule):
    return hmac.new(key, canon(rule), hashlib.sha256).hexdigest()[:16]


def rule_key(rule):
    """Consensus matches on threat + target_id only, so small AI differences don't break it."""
    return f"{rule['threat']}|{rule['target_id']}"
