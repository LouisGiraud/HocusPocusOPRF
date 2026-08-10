import random
import time

# ------------- Configuration -------------
p = 2**255 - 19
epsilon = 781764

# Prime factorization of epsilon: 2^2 * 3 * 65147
PRIME_FACTORS = [2, 3, 65147]

# ---------- Find a primitive epsilon-th root of unity ----------
def find_primitive_root():
    """
    Finds an element omega in F_p such that omega has exact order epsilon.
    """
    while True:
        # Pick a random field element
        h = random.randrange(2, p - 1)
        # Raise to (p-1)/epsilon to get an element whose order divides epsilon
        omega = pow(h, (p - 1) // epsilon, p)
        
        if omega == 1:
            continue  # Bad luck, try again
        
        # Check that omega is NOT a smaller-order root.
        # For each prime factor q of epsilon, omega^(epsilon/q) must NOT be 1.
        is_primitive = True
        for q in PRIME_FACTORS:
            if pow(omega, epsilon // q, p) == 1:
                is_primitive = False
                break
        
        if is_primitive:
            return omega

# ---------- Injectivity Test ----------
def test_truncation_injectivity(bytes_to_keep):
    """
    Enumerates all epsilon-th roots of unity and checks if truncating
    their canonical 32-byte representation to `bytes_to_keep` bytes
    yields any duplicates.
    """
    omega = find_primitive_root()
    print(f"  Using omega = {omega}")
    
    seen = set()
    current = 1  # omega^0 = 1
    
    # We'll also explicitly add 0 at the end, just to be thorough.
    # But 0 never collides with any root of unity anyway.
    
    start_time = time.time()
    for k in range(epsilon):
        # Pack into 32-byte little-endian (exactly what fe25519_pack does)
        packed_bytes = current.to_bytes(32, 'little')
        # Keep only the first 'bytes_to_keep' bytes
        truncated = packed_bytes[:bytes_to_keep]
        
        if truncated in seen:
            print(f"    ❌ Collision found at k={k}! ({truncated.hex()} already seen)")
            return False
        
        seen.add(truncated)
        
        # Next element: multiply by omega
        current = (current * omega) % p
        
        # Progress indicator (optional)
        if (k + 1) % 100000 == 0:
            print(f"    ... processed {k+1}/{epsilon} elements")
    
    elapsed = time.time() - start_time
    print(f"    ✅ No collisions found in {elapsed:.2f} seconds.")
    
    # Extra check: the zero element
    zero_packed = (0).to_bytes(32, 'little')
    zero_trunc = zero_packed[:bytes_to_keep]
    if zero_trunc in seen:
        print(f"    ❌ Zero element collides!")
        return False
    
    return True


# ---------- Main ----------
if __name__ == "__main__":
    print(f"Testing truncation injectivity for epsilon = {epsilon}")
    print("-" * 50)
    
    # Test a range of byte lengths
    for b in [4, 5, 6, 7, 8]:
        print(f"\n🔍 Testing {b} bytes ({b*8} bits) ...")
        if test_truncation_injectivity(b):
            print(f"  ✅ {b} bytes is INJECTIVE. Perfectly safe to use!")
        else:
            print(f"  ❌ {b} bytes has COLLISIONS. DO NOT USE.")