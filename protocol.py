# protocol.py

import secrets
from modular_math import modular_exponentiation
from parameters import generate_prime, validate_received_modulus, find_generator
from authentication import sign_message, verify_message

PROTOCOL_LABEL = "DH-CLASSROOM-AUTH-v1"

class Participant:
    def __init__(self, name, identity_key):
        self.name = name
        self.identity_key = identity_key
        self.verify_key = identity_key.public_key()
        self.pending_sessions = {}

    def create_initiation(self, responder_name, trusted_peer_verify_key):
        p, _ = generate_prime(bits=16)
        g = find_generator(p)
        ephemeral_priv = secrets.randbelow(p - 3) + 2
        ephemeral_pub = modular_exponentiation(g, ephemeral_priv, p)
        nonce_a = secrets.token_bytes(32).hex()

        payload = {
            "initiator": self.name,
            "nonce_a": nonce_a,
            "p": p,
            "g": g,
            "protocol": PROTOCOL_LABEL,
            "public_value_a": ephemeral_pub,
            "message_type": "init"
        }
        
        signature = sign_message(self.identity_key, payload)
        
        session_id = nonce_a
        self.pending_sessions[session_id] = {
            "priv": ephemeral_priv,
            "p": p,
            "g": g,
            "A": ephemeral_pub,
            "nonce_a": nonce_a,
            "responder": responder_name,
            "peer_key": trusted_peer_verify_key
        }

        return {"payload": payload, "signature": signature, "session_id": session_id}

    def handle_initiation(self, message_envelope, trusted_initiator_verify_key):
        payload = message_envelope["payload"]
        signature = message_envelope["signature"]

        if payload.get("protocol") != PROTOCOL_LABEL or payload.get("message_type") != "init":
            raise ValueError("Invalid protocol or message type[cite: 14].")
        
        if not verify_message(trusted_initiator_verify_key, payload, signature):
            raise ValueError("Initiator signature verification failed[cite: 14].")

        p = payload["p"]
        g = payload["g"]
        A = payload["public_value_a"]
        nonce_a = payload["nonce_a"]

        validate_received_modulus(p)
        if not (2 <= A <= p - 2):
            raise ValueError("Initiator public value A out of range[cite: 11, 14].")

        ephemeral_priv = secrets.randbelow(p - 3) + 2
        ephemeral_pub = modular_exponentiation(g, ephemeral_priv, p)
        nonce_b = secrets.token_bytes(32).hex()

        transcript = {
            "A": A,
            "B": ephemeral_pub,
            "g": g,
            "initiator": payload["initiator"],
            "nonce_a": nonce_a,
            "nonce_b": nonce_b,
            "p": p,
            "protocol": PROTOCOL_LABEL,
            "responder": self.name
        }

        response_payload = {
            "message_type": "response",
            "transcript": transcript
        }
        
        signature = sign_message(self.identity_key, response_payload)

        self.pending_sessions[nonce_a] = {
            "priv": ephemeral_priv,
            "p": p,
            "A": A,
            "B": ephemeral_pub,
            "transcript": transcript,
            "peer_key": trusted_initiator_verify_key
        }

        return {"payload": response_payload, "signature": signature, "nonce_a": nonce_a}

    def handle_response(self, message_envelope, session_id, trusted_responder_verify_key):
        payload = message_envelope["payload"]
        signature = message_envelope["signature"]

        if payload.get("message_type") != "response":
            raise ValueError("Expected response message type[cite: 15].")

        if not verify_message(trusted_responder_verify_key, payload, signature):
            raise ValueError("Responder signature verification failed[cite: 15].")

        session = self.pending_sessions.get(session_id)
        if not session:
            raise ValueError("Unknown or expired session state[cite: 15].")

        transcript = payload["transcript"]
        if transcript["p"] != session["p"] or transcript["g"] != session["g"] or transcript["A"] != session["A"]:
            raise ValueError("Transcript parameters do not match pending session[cite: 15].")

        B = transcript["B"]
        p = session["p"]
        if not (2 <= B <= p - 2):
            raise ValueError("Responder public value B out of range[cite: 11, 15].")

        session["B"] = B
        session["transcript"] = transcript

        finish_payload = {
            "message_type": "finish",
            "transcript": transcript
        }
        finish_signature = sign_message(self.identity_key, finish_payload)

        shared_secret = modular_exponentiation(B, session["priv"], p)
        session["shared_secret"] = shared_secret

        return {"payload": finish_payload, "signature": finish_signature}

    def handle_finish(self, message_envelope, nonce_a, trusted_initiator_verify_key):
        payload = message_envelope["payload"]
        signature = message_envelope["signature"]

        if payload.get("message_type") != "finish":
            raise ValueError("Expected finish message type[cite: 16].")

        session = self.pending_sessions.get(nonce_a)
        if not session:
            raise ValueError("Session not found or already completed[cite: 16].")

        if not verify_message(trusted_initiator_verify_key, payload, signature):
            raise ValueError("Finish signature verification failed[cite: 16].")

        shared_secret = modular_exponentiation(session["A"], session["priv"], session["p"])
        session["shared_secret"] = shared_secret
        
        del self.pending_sessions[nonce_a]
        return shared_secret
