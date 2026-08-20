import math
from collections import Counter

def generate_partitions(n, max_val=None):
    """Yields all integer partitions of n in descending order."""
    if max_val is None:
        max_val = n
    if n == 0:
        yield []
        return
    for i in range(min(n, max_val), 0, -1):
        for p in generate_partitions(n - i, i):
            yield [i] + p

def compute_C_max(partition, k):
    """Computes the product of the k largest elements from the multiset."""
    S = []
    for n_i in partition:
        S.extend(range(1, n_i + 1))
    S.sort(reverse=True)
    return math.prod(S[:k])

def compute_delta_pub_size(l_com, k, epsilon, success_threshold=2**-64):
    """Computes total_valid_deltas for a specific (l_com, k) pair efficiently."""
    threshold_T = success_threshold * math.perm(l_com, k)
    total_valid_deltas = 0
    
    for P in generate_partitions(l_com):
        m = len(P)
        if m > epsilon:
            continue

        # --- LOOK-AHEAD EARLY STOP FOR PARTITIONS ---
        max_allowed = P[0]
        best_future_partition = []
        rem = l_com
        while rem > 0:
            take = min(rem, max_allowed)
            best_future_partition.append(take)
            rem -= take
            
        if compute_C_max(best_future_partition, k) <= threshold_T:
            break
        # --------------------------------------------

        if compute_C_max(P, k) > threshold_T:
            f_c_counts = Counter(P).values()
            
            symbol_assignments = math.perm(epsilon, m)
            for f_c in f_c_counts:
                symbol_assignments //= math.factorial(f_c)
                
            sequence_arrangements = math.factorial(l_com)
            for n_i in P:
                sequence_arrangements //= math.factorial(n_i)
                
            total_valid_deltas += (symbol_assignments * sequence_arrangements)
            
    return total_valid_deltas


def evaluate_configuration(l_com, k, epsilon, logp):
    """
    Evaluates a single, specific (l_com, k) configuration.
    Returns: (wkcr_bound, cost_bytes)
    """
    cost = 3 * l_com + 290 * k # Makes some assumption about epsilon, not generic yet
    total_deltas = compute_delta_pub_size(l_com, k, epsilon) 
    
    if total_deltas == 0:
        return float('-inf'), cost
        
    log2_deltas = math.log2(total_deltas)
    log2_eps = math.log2(epsilon)
    nu = l_com / (2**logp - l_com)
    wkcr = (2 * log2_deltas) + (2 * logp) - 1 - log2_eps + l_com * math.log2(1/epsilon + nu) + math.log2(1 + (2 * l_com / (2**logp)) * (1/epsilon + nu)**(-2))
    
    return wkcr, cost


def fuzz_parameters_optimized(epsilon, logp, target_wkcr=-64.0, tolerance=10.0):
    """
    Fuzzes over values of l_com and k using the factored evaluation function
    and the requested pruning rules.
    """
    valid_candidates = []
    min_lcom = 40
    max_lcom = 120
    
    print(f"{'l_com':<8}{'k':<6}{'WKCR Bound':<15}{'Cost (Bytes)':<12}")
    print("-" * 43)
    
    for l_com in range(min_lcom, max_lcom + 1):
        
        # Optimization 1: Evaluate the maximum possible k boundary condition first
        initial_wkcr, _ = evaluate_configuration(l_com, l_com, epsilon, logp)
            
        # If the absolute best case (k = l_com) fails our security threshold, 
        # lower values of k will only be worse. Skip this l_com entirely.
        if initial_wkcr > target_wkcr:
            continue
            
        # Optimization 2: k must be > l_com / 2
        min_k_allowed = math.floor(l_com / 2) + 1
        
        # Sweep k downwards starting from l_com down to the floor limit
        for k in range(l_com, min_k_allowed - 1, -1):
            wkcr, cost = evaluate_configuration(l_com, k, epsilon, logp)
            
            # If it slips past the target metric limit into completely insecure territory, 
            # stop checking lower k values for this l_com line.
            if wkcr > target_wkcr:
                break
                
            # Store valid candidates within the metric window
            if wkcr <= target_wkcr and wkcr >= (target_wkcr - tolerance):
                valid_candidates.append((l_com, k, wkcr, cost))
                print(f"{l_com:<8}{k:<6}{wkcr:<15.2f}{cost:<12}")
                
    # Sort results by the objective cost payload size (lowest cost first)
    valid_candidates.sort(key=lambda x: x[3])
    return valid_candidates

# =====================================================================
# Execution Examples
# =====================================================================
epsilon_val = 781764
logp_val = 256

# Optimal pair by fuzzer : 61,53

# Example 1: Isolated evaluation of a specific single pair
# print("--- Single Pair Test ---")
# test_lcom, test_k = 61, 53
# res_wkcr, res_cost = evaluate_configuration(test_lcom, test_k, epsilon_val, logp_val)
# print(f"Result for l_com={test_lcom}, k={test_k}: WKCR={res_wkcr:.2f}, Cost={res_cost} bytes\n")


# # Example 2: Running the optimized fuzzing sweep
# print("--- Starting Optimization Search Grid ---")
# optimal_pairs = fuzz_parameters_optimized(epsilon=epsilon_val, logp=logp_val, target_wkcr=-64.0, tolerance=15.0)

# if optimal_pairs:
#     print("\nTop 5 Most Optimal Configurations (by minimal byte size):")
#     for i, (l, k, bound, cost) in enumerate(optimal_pairs[:5], 1):
#         print(f"{i}. l_com={l}, k={k} | WKCR={bound:.2f} | Cost={cost} bytes")