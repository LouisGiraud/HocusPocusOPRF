# generate_fast_ops.py

def get_sliding_window_code(exp, func_name, w=5):
    bin_exp = bin(exp)[2:] # Binary string of the exponent
    
    code = []
    code.append(f"    // Automatically generated sliding-window (w={w}) addition chain")
    code.append(f"    // Exponent length: {len(bin_exp)} bits")
    code.append(f"    static void {func_name}(fe25519* out, const fe25519* in_val) {{")
    code.append("        fe25519 x = *in_val;")
    
    # Declare precomputed window variables
    max_odd = (1 << w) - 1
    odd_vars = [f"x{k}" for k in range(3, max_odd + 1, 2)]
    code.append(f"        fe25519 x2, {', '.join(odd_vars)};")
    
    # Execute Precomputation
    code.append("        fe25519_square(&x2, &x);")
    for k in range(3, max_odd + 1, 2):
        prev = "x" if k == 3 else f"x{k-2}"
        code.append(f"        fe25519_mul(&x{k}, &x2, &{prev});")
        
    code.append("        fe25519 t;")
    
    # Execute Sliding Window
    i = 0
    is_first = True
    while i < len(bin_exp):
        if bin_exp[i] == '0':
            if not is_first:
                code.append("        fe25519_square(&t, &t);")
            i += 1
        else:
            # Look ahead up to w bits for a window ending in '1'
            max_len = 1
            for j in range(1, w + 1):
                if i + j <= len(bin_exp) and bin_exp[i + j - 1] == '1':
                    max_len = j
            
            val = int(bin_exp[i:i+max_len], 2)
            
            if is_first:
                val_str = "x" if val == 1 else f"x{val}"
                code.append(f"        t = {val_str};")
                is_first = False
            else:
                for _ in range(max_len):
                    code.append("        fe25519_square(&t, &t);")
                val_str = "x" if val == 1 else f"x{val}"
                code.append(f"        fe25519_mul(&t, &t, &{val_str});")
            i += max_len
            
    code.append("        *out = t;")
    code.append("    }")
    return "\n".join(code)

# 1. Define the Math
p = 2**255 - 19
eps = 781764
d = (p - 1) // eps

# pow(eps, -1, d) is Python 3.8+ native modular inverse
y = d - pow(eps, -1, d)

# 2. Output the C++ File content
print("""#include "fast_residue_25519.h"
#include <cstring>
#include <cryptoTools/Crypto/PRNG.h>
#include "./field25519/fe25519.h"
#include "voleUtils.h"

namespace FastResidue25519 {

// Ugly hardcoded fast exponentiators (generated with generate_fast_ops.py)


""")

# Generate the three unrolled exponentiation helpers
print(get_sliding_window_code(eps, "pow_eps", w=4))
print("\n")
print(get_sliding_window_code(d, "pow_D", w=5))
print("\n")
print(get_sliding_window_code(y, "pow_Y", w=5))

# Print the cleanly linked API functions
print("""
    // --- Computations ---
    
    uint32_t presidue_eps(const fe25519& val){
        fe25519 res;
        pow_D(&res, &val);
        res.freeze();
        
        return res.v[0] | ((uint32_t)res.v[1] << 8) | ((uint32_t)res.v[2] << 16);
    }

    uint32_t presidue_eps_prime(const fe25519& val){
        return presidue_eps(val);
    }

    fe25519 pow_inv_eps_prime(const fe25519& a){
        fe25519 res;
        pow_Y(&res, &a);
        return res;
    }

    fe25519 fast_pow_eps(const fe25519& val){
        fe25519 res;
        pow_eps(&res, &val);
        return res;
    }

    // --- Generators ---

    fe25519 random_power_eps(osuCrypto::PRNG& prng){
        fe25519 r;
        random_fe25519(&r, prng);
        return fast_pow_eps(r);
    }

    fe25519 random_power_eps_prime(osuCrypto::PRNG& prng){
        return random_power_eps(prng);
    }

    // --- Packing ---

    void pack(uint8_t* buffer, uint32_t symbol){
        for (int i = 0; i < SYMBOL_BYTES; ++i) {
            buffer[i] = static_cast<uint8_t>((symbol >> (8 * i)) & 0xFF);
        }
    }

    uint32_t unpack(const uint8_t* buffer){
        uint32_t symbol = 0;
        for (int i = 0; i < SYMBOL_BYTES; ++i) {
            symbol |= (static_cast<uint32_t>(buffer[i]) << (8 * i));
        }
        return symbol;
    }
}
""")