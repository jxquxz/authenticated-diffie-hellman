# authentication.py

import json

def serialize_payload(payload_dict):
    """
    Serializes a dictionary using strict schema rules:
    sorted keys, compact separators, UTF-8 encoding[cite: 13].
    """
    return json.dumps(payload_dict, sort_keys=True, separators=(",", ":")).encode("utf-8")

def sign_message(signing_key, payload_dict):
    payload_bytes = serialize_payload(payload_dict)
    signature_bytes = signing_key.sign(payload_bytes)
    return signature_bytes.hex()

def verify_message(verify_key, payload_dict, signature_hex):
    payload_bytes = serialize_payload(payload_dict)
    try:
        verify_key.verify(payload_bytes, bytes.fromhex(signature_hex))
        return True
    except (ValueError, TypeError):
        return False
