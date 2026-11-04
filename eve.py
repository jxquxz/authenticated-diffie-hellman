# eve.py

from Crypto.PublicKey import Ed25519
from protocol import Participant
from authentication import sign_message

def simulate_eve_attack():
    print("\n--- Running Eve's MitM Attack Simulation ---")
    alice_key = Ed25519.generate()
    bob_key = Ed25519.generate()
    eve_key = Ed25519.generate()

    alice = Participant("Alice", alice_key)
    bob = Participant("Bob", bob_key)
    eve = Participant("Eve", eve_key)

    # Alice initiates exchange intended for Bob, but intercepted by Eve
    init_msg = alice.create_initiation("Bob", bob.verify_key)
    
    # Eve tampers with the public value A or substitutes parameters
    print("[Eve] Intercepted Alice's initiation and modified public value A.")
    init_msg["payload"]["public_value_a"] = 999  # Invalid value substitution

    try:
        # Bob processes the tampered message
        bob.handle_initiation(init_msg, alice.verify_key)
    except ValueError as e:
        print(f"✅ Attack Defeated Successfully! Bob rejected the message: {e}")

if __name__ == "__main__":
    simulate_eve_attack()
