# Project Report: Authenticated Diffie-Hellman Key Exchange

## 1. Implementation Overview
* **Square-and-Multiply ('modular_math.py'):** Computes base^{exponent} \pmod{modulus}manually by iterating over the binary representation of the exponent in O(log e) time without using built-in Python power shortcuts.
* **Prime Generation & Factorization ('parameters.py'):** Utilizes PyCryptodome's 'getPrime' with 'secrets.token_bytes' to safely generate exact 16–32-bit primes. Uses trial division to extract distinct prime factors of p - 1 and verifies primitive root generators.
* **Authentication & Protocol ('authentication.py', 'protocol.py'):** Enforces strict JSON serialization, 32-byte nonces, and Ed25519 digital signatures across a 3-phase handshake ('init', 'response', 'finish') to prevent replay and Man-in-the-Middle attacks.

---

## 2. Research Comparison: Finite-Field Diffie-Hellman vs. ECDH

Finite-field Diffie-Hellman (FFDH) relies on the hardness of the discrete logarithm problem over the multiplicative group of integers modulo a prime p. In contrast, Elliptic-Curve Diffie-Hellman (ECDH) operates over algebraic structures on elliptic curves, deriving security from the elliptic-curve discrete logarithm problem (ECDLP).

First, key sizes and operations differ vastly. FFDH uses modular exponentiation, requiring large moduli (e.g., 2048+ bits) to maintain security because sub-exponential index-calculus attacks apply to finite fields. ECDH replaces modular exponentiation with scalar multiplication on elliptic curves (repeated point additions and doublings). Because index-calculus does not apply to general elliptic curves, a much smaller 256-bit ECDH key provides security equivalent to a 3072-bit FFDH key, drastically reducing computation time and network payload sizes.

Second, our project uses tiny 16-to-32-bit primes for instructional clarity, rapid debugging, and manual trace visibility. However, these small sizes are entirely insecure in the real world because a modern computer can crack them via trial division or brute-force in milliseconds. Furthermore, factoring p - 1 via trial division works for small classroom primes, but becomes computationally impossible for massive 2048-bit production primes.

Third, fresh ephemeral keys (used in ECDHE) ensure **forward secrecy**. If an attacker later steals a user's long-term identity signing key, they still cannot decrypt past session transcripts because the temporary exchange keys were destroyed.

Finally, raw key exchanges are vulnerable to Man-in-the-Middle (MitM) attacks. Just like our project demonstrates with Eve, public keys do not prove identity by themselves, which is why digital signatures (like Ed25519) and authenticated protocols are mandatory. In production, developers never write custom crypto or use arbitrary primes; they rely on standardized curves and audited cryptographic libraries like PyCryptodome.

### References
1. RFC 9528: Ephemeral Diffie-Hellman Over COSE (EDHOC).
2. Certicom Research: SEC 1: Elliptic Curve Cryptography, Version 2.0.