# modular_math.py

def modular_exponentiation(base, exponent, modulus):
    """
    Calculates base^exponent mod modulus using the manual square-and-multiply algorithm.
    Validates inputs, types, and rejects invalid bounds or types[cite: 4, 5].
    """
    if not isinstance(base, int) or not isinstance(exponent, int) or not isinstance(modulus, int):
        raise ValueError("Inputs must be integers[cite: 4, 5].")
    
    if modulus <= 0:
        raise ValueError("Modulus must be a positive integer greater than 0[cite: 4, 5].")
    if exponent < 0:
        raise ValueError("Exponent must be a non-negative integer[cite: 4, 5].")
    
    if modulus == 1:
        return 0

    # Exact steps specified in instructions[cite: 4]
    result = 1 % modulus
    base = base % modulus
    
    while exponent > 0:
        if exponent % 2 == 1:
            result = (result * base) % modulus
        base = (base * base) % modulus
        exponent = exponent // 2
        
    return result
