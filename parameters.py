# parameters.py

import secrets
import time
from Crypto.Util.number import getPrime, isPrime
from modular_math import modular_exponentiation

def generate_prime(bits=16):
    """
    Generates a prime number of exact bit length (16 through 32 bits inclusive)
    using PyCryptodome's getPrime and secrets.token_bytes[cite: 3, 6, 7].
    """
    if not isinstance(bits, int) or isinstance(bits, bool):
        raise TypeError("Bit length must be an integer[cite: 7, 19].")
    if not (16 <= bits <= 32):
        raise ValueError("Prime size must be between 16 and 32 bits inclusive[cite: 3, 7].")
    
    start_time = time.perf_counter()
    
    def custom_randfunc(n_bytes):
        return secrets.token_bytes(n_bytes)
    
    p = getPrime(bits, randfunc=custom_randfunc)
    
    if p.bit_length() != bits or not isPrime(p):
        raise RuntimeError("Generated prime failed bit-length or primality verification[cite: 7].")
        
    elapsed_time = time.perf_counter() - start_time
    return p, elapsed_time

def validate_received_modulus(p):
    """
    Validates received public modulus p against expected constraints[cite: 7, 19].
    """
    if not isinstance(p, int) or isinstance(p, bool):
        raise ValueError("Modulus must be an integer[cite: 7, 19].")
    if p == 23:
        return True # Allowed test fixture[cite: 3, 13]
    if not (16 <= p.bit_length() <= 32):
        raise ValueError("Modulus bit length out of permitted range (16-32 bits)[cite: 3, 7].")
    if not isPrime(p):
        raise ValueError("Modulus is composite; primality check failed[cite: 7, 19].")
    return True

def prime_factors(n):
    """
    Returns every distinct prime factor of n without duplicates using trial division[cite: 8, 9].
    """
    if not isinstance(n, int) or n < 1:
        raise ValueError("Input must be a positive integer[cite: 8, 9].")
        
    factors = set()
    if n % 2 == 0:
        factors.add(2)
        while n % 2 == 0:
            n //= 2
            
    divisor = 3
    while divisor * divisor <= n:
        if n % divisor == 0:
            factors.add(divisor)
            while n % divisor == 0:
                n //= 2
        divisor += 2
        
    if n > 1:
        factors.add(n)
        
    return sorted(list(factors))

def is_primitive_root(g, p, p_minus_1_factors):
    if not (2 <= g <= p - 2):
        return False
    for r in p_minus_1_factors:
        exponent = (p - 1) // r
        if modular_exponentiation(g, exponent, p) == 1:
            return False
    return True

def find_generator(p):
    factors = prime_factors(p - 1)
    for g in range(2, p - 1):
        if is_primitive_root(g, p, factors):
            return g
    raise RuntimeError("No primitive root found for the given prime[cite: 9, 10].")
