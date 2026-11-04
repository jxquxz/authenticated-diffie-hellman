# test_suite.py

import unittest
from Crypto.PublicKey import Ed25519
from modular_math import modular_exponentiation
from parameters import generate_prime, validate_received_modulus, prime_factors, find_generator, is_primitive_root
from protocol import Participant

class TestCryptographicProject(unittest.TestCase):

    def test_square_and_multiply_known_values(self):
        # Example from instructions: 5^6 mod 23 = 8[cite: 5]
        self.assertEqual(modular_exponentiation(5, 6, 23), 8)
        self.assertEqual(modular_exponentiation(5, 0, 23), 1)
        self.assertEqual(modular_exponentiation(5, 6, 1), 0)

    def test_square_and_multiply_invalid_inputs(self):
        with self.assertRaises(ValueError):
            modular_exponentiation(5, -1, 23)
        with self.assertRaises(ValueError):
            modular_exponentiation(5, 2, 0)

    def test_prime_generation_bounds(self):
        p, _ = generate_prime(16)
        self.assertTrue(32768 <= p <= 65535)[cite: 3]
        self.assertEqual(p.bit_length(), 16)[cite: 7]
        
        with self.assertRaises(ValueError):
            generate_prime(12)[cite: 3] # Below 16 bits
        with self.assertRaises(ValueError):
            generate_prime(35) # Above 32 bits

    def test_modulus_validation(self):
        self.assertTrue(validate_received_modulus(23))[cite: 3, 13] # Test fixture prime
        with self.assertRaises(ValueError):
            validate_received_modulus(32769)[cite: 7, 19] # Composite number

    def test_factorization(self):
        self.assertEqual(prime_factors(22), [2, 11])[cite: 8] # p = 23 -> p - 1 = 22
        self.assertEqual(prime_factors(65536), [2])[cite: 8] # p = 65537 -> 2^16
        self.assertEqual(prime_factors(1), [])[cite: 8]

    def test_generator_verification(self):
        factors_22 = prime_factors(22)
        self.assertTrue(is_primitive_root(5, 23, factors_22))[cite: 9, 19]
        self.assertFalse(is_primitive_root(2, 23, factors_22))[cite: 9, 19]

    def test_full_authenticated_exchange(self):
        alice_key = Ed25519.generate()
        bob_key = Ed25519.generate()

        alice = Participant("Alice", alice_key)
        bob = Participant("Bob", bob_key)

        init_msg = alice.create_initiation("Bob", bob.verify_key)
        response_msg = bob.handle_initiation(init_msg, alice.verify_key)
        finish_msg = alice.handle_response(response_msg, init_msg["session_id"], bob.verify_key)
        bob_secret = bob.handle_finish(finish_msg, init_msg["nonce_a"], alice.verify_key)
        alice_secret = alice.pending_sessions[init_msg["nonce_a"]]["shared_secret"]

        self.assertEqual(alice_secret, bob_secret)

    def test_attack_tampered_public_value(self):
        alice_key = Ed25519.generate()
        bob_key = Ed25519.generate()

        alice = Participant("Alice", alice_key)
        bob = Participant("Bob", bob_key)

        init_msg = alice.create_initiation("Bob", bob.verify_key)
        init_msg["payload"]["public_value_a"] = 999  # Tamper with A

        with self.assertRaises(ValueError):
            bob.handle_initiation(init_msg, alice.verify_key)

if __name__ == "__main__":
    unittest.main()
