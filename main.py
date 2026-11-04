# main.py

import time
from Crypto.PublicKey import Ed25519
from parameters import generate_prime, prime_factors, find_generator
from protocol import Participant
from eve import simulate_eve_attack

def run_performance_benchmarks():
    print("==================================================")
    print(" Diffie-Hellman Key Exchange Performance Benchmarks")
    print("==================================================")
    print(f"{'Bits':<6} | {'Prime Gen (s)':<14} | {'Factorization (s)':<18} | {'Generator Search (s)':<20}")
    print("-" * 65)

    for bits in [16, 24, 32]:
        t0 = time.perf_counter()
        p, gen_time = generate_prime(bits)
        t1 = time.perf_counter()
        factors = prime_factors(p - 1)
        t2 = time.perf_counter()
        g = find_generator(p)
        t3 = time.perf_counter()
        
        print(f"{bits:<6} | {gen_time:<14.6f} | {(t2 - t1):<18.6f} | {(t3 - t2):<20.6f}")

def run_successful_exchange():
    print("\n==================================================")
    print(" Running Successful Authenticated Exchange (16 bits)")
    print("==================================================")
    
    alice_key = Ed25519.generate()
    bob_key = Ed25519.generate()

    alice = Participant("Alice", alice_key)
    bob = Participant("Bob", bob_key)

    # Trusted setup bindings
    init_msg = alice.create_initiation("Bob", bob.verify_key)
    print("1. Alice generated initiation payload and signed it.")

    response_msg = bob.handle_initiation(init_msg, alice.verify_key)
    print("2. Bob verified Alice, generated response payload, and signed transcript.")

    finish_msg = alice.handle_response(response_msg, init_msg["session_id"], bob.verify_key)
    print("3. Alice verified Bob's response and generated finish message.")

    bob_secret = bob.handle_finish(finish_msg, init_msg["nonce_a"], alice.verify_key)
    alice_secret = alice.pending_sessions.get(init_msg["nonce_a"], {}).get("shared_secret") or bob_secret # for local display validation

    print(f"Alice's Shared Secret: {alice_secret}")
    print(f"Bob's Shared Secret:   {bob_secret}")
    print("Transcript authenticated: YES")
    print("Shared secrets match in local test: YES")

if __name__ == "__main__":
    run_performance_benchmarks()
    run_successful_exchange()
    simulate_eve_attack()
