import sys
import os
sys.path.append(os.getcwd())

from dpub import evaluate_configuration

def verify_parameters(parameters):
    """
    Verifies if a given set of parameters satisfies the 128-bit computational 
    and 64-bit statistical security constraints for the Power Residue OPRF.
    """

    # Adversary query budgets
    n_h1 = 2**112
    n_h2 = 2**128

    (p_bits, epsilon, epsilon_prime, l_com, l_eval, k) = parameters
    d=8
    
    results = {
        "valid_domain": False,
        "p_bounds": False,
        "omu_pass": False,
        "dsprs_pass": False,
        "wkcr_pass": False,
        "all_pass": False,
        "details": {}
    }

    # 0. Domain Checks
    if k > l_com:
        results["details"]["domain"] = "Failed: k cannot exceed l_com"
        return results
    
    results["valid_domain"] = True

    # 1. Prime size bounds (n_H1 / p <= 1 => p >= n_H1) + 4/p term (should always pass) + leval²/2p term
    p_approx = 2^p_bits
    max_val = max(n_h1, 2^66, l_eval^2 * 2^63, (n_h1^2)*(l_eval^4) / 8)
    results["p_bounds"] = (p_approx >= max_val) # Should have gt 250 bit prime
    
    # 2. OMU Constraint: (epsilon')^{l_eval} >= n_H2
    omu_strength = log(epsilon_prime^l_eval, 2).n()
    n_h2_bits = log(n_h2, 2).n()
    results["omu_pass"] = (omu_strength >= n_h2_bits)
    results["details"]["omu_bits"] = int(omu_strength)

    # 3. DSPRS PQ Security Constraint
    # requires 2^256 sized prime
    results["dsprs_pass"] = (p_bits >= 256)
    results["details"]["p_bits"] = int(p_bits)

    # 4. WKCR Constraint: Computed in dpub.py
    wkcr_strength = -evaluate_configuration(l_com, k, epsilon, p_bits)[0]
    
    results["wkcr_pass"] = (wkcr_strength >= 64)
    results["details"]["wkcr_bits"] = int(wkcr_strength)
    
    # Overall Evaluation
    results["all_pass"] = all([
        results["p_bounds"],
        results["omu_pass"], 
        results["dsprs_pass"], 
        results["wkcr_pass"]
    ])

    return results


def estimate_cost(parameters):
    (p_bits, epsilon, epsilon_prime, l_com, l_eval, k) = parameters
    cost = {
        "Base OTs" : 0,
        "VOLE" : 0,
        "Quicksilver" : 0,
        "Direct communication" : 0,
        "Total" : 0
    }
    element_size = ceil(p_bits / 8) # num bytes for 1 Fp element
    presidue_size = ceil(log(epsilon, 2) / 8) # num bytes for 1 epsilon presidue
    presidue_prime_size = ceil(log(epsilon_prime, 2) / 8) # num bytes for 1 epsilon_prime presidue

    t_param = 8 # communication opt param for sVOLE, recommended to be 8 by author
    s_param = 64 # statistical security

    num_ot = 128
    cost["Base OTs"] += 2*(800+768) * num_ot # cost per OT in Bytes (2*(kyberkey + kybercypher) * num_OT)

    vole_vec_number = (1 + ceil((p_bits + 2*s_param) / t_param))
    vole_vec_length = l_eval + 1
    cost["VOLE"] += vole_vec_number * vole_vec_length * element_size # VOLE+ exe In Bytes

    num_quicksilver_vec = ceil(s_param / t_param) # 8
    quicksilver_witness_size_base = 4 + l_eval + k


    d=5 # Found through some fuzzign
    w_extra = 12

    quicksilver_witness_size_extra = d + w_extra
    cost["Quicksilver"] += num_quicksilver_vec * (quicksilver_witness_size_base + quicksilver_witness_size_extra) * element_size
    
    # Direct communication
    e_size = l_com * presidue_size
    c_size = k * 2 # k elements in [lcom], we assume we can store elemts in [lcom] over two bytes (assuming lcom lt 2^16)
    m_size = k * element_size # k Fp elements
    cost["Direct communication"] += e_size + c_size + m_size

    cost["Total"] = sum(cost.values())

    return cost


def fuzz_optimal_parameters():
    """
    Fuzzes the parameter space to find the configuration that passes all 
    security constraints while minimizing the total communication cost.
    """
    best_cost = float('inf')
    best_params = None
    best_cost_breakdown = None
    
    # 1. Define sensible parameter grids
    p_bits_options = [256]
    
    epsilons = [2^2 * 3 * 65147] 
    epsilons_prime = [2^2, 3, 2^2 * 3, 65147, 2^2*65147, 3*65147, 2^2*3*65147]
    
    l_com_options = [61]
    k_options = [55]

    print("Starting smart fuzzer...")

    for p_bits in p_bits_options:
        for epsilon in epsilons:
            for epsilon_prime in epsilons_prime:
                
                # SMART INCENTIVE 1: OMU Pruning
                # l_eval * log2(epsilon_prime) >= 128 
                min_l_eval = math.ceil(128 / log(epsilon_prime, 2))
                
                # We only search a tight window above the minimum l_eval 
                for l_eval in range(min_l_eval, min_l_eval + 10):
                    
                    for l_com in l_com_options:
                        # SMART INCENTIVE 3: Quicksilver cost minimization
                        # k affects Soundness but increases QS witness size. Keep it as small as possible.
                        for k in k_options:
                            params = (p_bits, epsilon, epsilon_prime, l_com, l_eval, k)
                            
                            # Evaluate
                            res = verify_parameters(params)
                            
                            if res["all_pass"]:
                                current_cost = estimate_cost(params)
                                
                                # Track the minimum cost
                                if current_cost["Total"] < best_cost:
                                    best_cost = current_cost["Total"]
                                    best_params = params
                                    best_cost_breakdown = current_cost
                                    
                                    print(f"--> New optimal found: {float(best_cost) / 1000:.2f} KB")
                                    print(f"    Params: (p={p_bits}, eps={epsilon}, eps'={epsilon_prime}, l_com={l_com}, l_eval={l_eval}, k={k})")

    print("\n=== FUZZING COMPLETE ===")
    if best_params:
        print(f"Optimal Parameters: {best_params}")
        for key, val in best_cost_breakdown.items():
            print(f"{key}: {int(val / 1000)} KB")
    else:
        print("No valid parameters found in the given search space.")
        
    return best_params, best_cost_breakdown

# Run the fuzzer
# best_p, best_c = fuzz_optimal_parameters()


# Optimal Parameters: (256, 4294967296, 4294967296, 100, 4, 61, 69)
# Base OTs: 12 KB
# VOLE: 7 KB
# Quicksilver: 29 KB
# Direct communication: 5 KB
# Total: 55 KB
# Prime number : 
    # p = 57896044618658097711785492504343953926634992332820283228654611618590034493441
    # g = 13479973333575319897333507543509815336818572211270286522026781835265
    # Bit length of p: 256
    # Is prime: True

    # Exact shape for C++ fast reduction:
    # p = 2^255 + 2^80 + 2^32 + 2^0 = 2^32 * (2^223 + 2^48 + 1) + 1
    # g = 2^223 + 2^48 + 1


# --- Example Usage --- (p_bits, epsilon, epsilon_prime, l_com, l_eval, k) = parameters
#parameters = (256, 4294967296, 4294967296, 100, 4, 61, 69)
parameters = (256, 781764, 781764, 61, 10, 53)
res = verify_parameters(parameters)
# print(res)
cost = estimate_cost(parameters)

for key, val in res.items():
    print(f"{key}: {val}")  

for key, val in cost.items():
    print(f"{key}: {int(val / 1000)} KB")



# [Optimization] lambda=32: Optimal step size phi=2. Yields d=4, w_extra=22 (Total=26)

# === FUZZING COMPLETE ===
# Optimal Parameters: (256, 4294967296, 4294967296, 100, 4, 61, 70)
# Base OTs: 401 KB
# VOLE: 7 KB
# Quicksilver: 25 KB
# Direct communication: 2 KB
# Total: 437 KB