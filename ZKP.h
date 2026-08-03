#ifndef PROPRF_ZK_PROOF
#define PROPRF_ZK_PROOF

#include <coroutine>
#include "libOTe/config.h"

#include "libOTe/TwoChooseOne/OTExtInterface.h"
#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Crypto/PRNG.h>
#include <cryptoTools/Common/BitVector.h>
#include <cryptoTools/Common/Aligned.h>
#include <cryptoTools/Common/MatrixView.h>
#include <cryptoTools/Network/Channel.h>
#include "libOTe/TwoChooseOne/TcoOtDefines.h"
#include "libOTe/Tools/Coproto.h"
#include "libOTe/Tools/Pprf/RegularPprf.h"
#include "coproto/Socket/AsioSocket.h"
#include <stdio.h>
#include "smallSetVoleFast.h"
#include <string>
#include "voleUtils.h"

using namespace osuCrypto;

// arithmetic for low-degree polynomials with coefficients in fe25519.

template<long unsigned int D> 
struct poly {
    std::array<fe25519,D+1> coefs;
};

template<long unsigned int D>
void reduce_poly(poly<D> &poly){
    for (size_t i = 0; i <= D; i++)
    {
        poly.coefs[i].reduce_add_sub();
        poly.coefs[i].freeze();
    }
}

template<long unsigned int D>
void set_zero_poly(poly<D> &poly){
    for (size_t i = 0; i <= D; i++)
    {
        poly.coefs[i].setzero();
    }
}

template<long unsigned int D1, long unsigned int D2>
void operator += (poly<D1> &lhs, const poly<D2> &rhs){
    for (size_t i = 0; i <= D2; i++)
    {
        lhs.coefs[i] += rhs.coefs[i];
    }
}

template<long unsigned int D1, long unsigned int D2>
void operator -= (poly<D1> &lhs, const poly<D2> &rhs){
    for (size_t i = 0; i <= D2; i++)
    {
        lhs.coefs[i] -= rhs.coefs[i];
    }
}

template<long unsigned int D1, long unsigned int D2>
poly<D1> shift_up (const poly<D2> &in){
    poly<D1> out;
    for (size_t i = 0; i < D1 - D2; i++)
    {
        out.coefs[i].setzero();
    }
    
    for (size_t i = 0; i <= D2; i++)
    {
        out.coefs[i + D1 - D2] = in.coefs[i];
    }
    return out;
}

template<long unsigned int D>
poly<D> operator + (const poly<D> &lhs, const poly<D> &rhs){
    poly<D> out;
    for (size_t i = 0; i <= D; i++)
    {
        out.coefs[i] = lhs.coefs[i] + rhs.coefs[i];
    }
    return out;
}

template<long unsigned int D1, long unsigned int D2>
poly<D1 + D2> operator * (const poly<D1> &lhs, const poly<D2> &rhs){
    poly<D1 + D2> out;
    for (size_t i = 0; i <= D1 + D2; i++)
    {
        fe25519_setzero(&out.coefs[i]);
    }
    
    for (size_t i = 0; i <= D1; i++)
    {
        for (size_t j = 0; j <= D2; j++)
        {
            out.coefs[i+j] += lhs.coefs[i]*rhs.coefs[j];
        }
    }

    reduce_poly(out);
    return out;
}

// 79 witness elements (index 0 to 78, careful about indexing)
#define K_pos 0 
#define v_offset 1 // v_i = w[i + v_offset] for i = 0 to 9
#define b_offset 11 // b_i = w[i + b_offset] for i = 0 to 52
#define ru_pos 64
#define rv_pos 65
#define y_offset 66 // y_i = w[i + y_offset] for i = 0 to 8
#define a0_pos 75
#define a1_pos 76
#define c0_pos 77
#define c1_pos 78

// --- ZK Protocol Requirements --- (Added to witness : final size 85)
#define mask_pos 79  // 5 masks: A0*, A1*, A2*, A3*, A4*
#define check_pos (mask_pos + 5) // 1 element for the VOLE consistency check

class PROPRF_ZKProver
{
public:
    int leval;
    int lcom;
    int k;
    int small_set_bits;
    int statistical_security_bits;
    int k_vole;
    int vole_len;
    std::vector<poly<1>> state;

    PROPRF_ZKProver(int leval, int lcom, int k, int small_set_bits, int statistical_security_bits) : leval(leval),
                                                                          lcom(lcom),
                                                                          k(k),
                                                                          small_set_bits(small_set_bits),
                                                                          statistical_security_bits(statistical_security_bits)
    {
        k_vole = (statistical_security_bits + small_set_bits - 1)/ small_set_bits;
        vole_len = 4 + leval + k + 12 + 5 + 1; // (4 + leval + k) base witness elements + 12 extra witness elements + 5 masks (A* elements for d=5) + 1 random element (not sure what this is yet)
    };

    task<> commit_to_witness(std::vector<fe25519> &w, 
        std::vector<std::vector<fe25519>>& ui, 
        std::vector<std::vector<fe25519>>& vi, 
        PRNG &prng, Socket &chl){

        // 1. Initialize MACs to zero (the degree-0 coef)
        state.resize(vole_len);
        for (size_t i = 0; i < vole_len; i++)
        {
            state[i].coefs[0].setzero();
        }

        // 2. Write the 79 witness elements into the state (degree 1 slot)
        // (state[0] gets w[0], state[78] gets w[78])
        for (size_t i = 0; i < 79; i++)
        {
            state[i].coefs[1] = w[i];
        }
        
        // 3. Setup the 5 ZK Masks (this is supposed to be a VOPE call but we can make it simpler by making the prover
        // generate it and constructing B* in the verifier accordingly)
        for (size_t i = 0; i < 5; i++)
        {
            random_fe25519(&state[mask_pos + i].coefs[1], prng);
        }

        // ==========================================================
        // 4. VOLE Shift & Network Transfer
        // ==========================================================
        // TODO: we can save leval+7 field elements worth of communication (~= 4.3 KB) 
        // by derandomizing  a, ru, rc, and mask to v_0 instead of to some randomly chosen value 

        std::vector<unsigned char> buffer(k_vole*vole_len*PRIME_BYTES);
        for (size_t i = 0; i < k_vole; i++)
        {
            fe25519 multiplier;
            multiplier.setzero();
            multiplier.v[(i*small_set_bits)/8] = (1 << ((i*small_set_bits) % 8));

            for (size_t j = 0; j < vole_len; j++)
            {
                // compute derandomization to send to the verifier
                fe25519 temp = state[j].coefs[1] - vi[i][j];
                temp.reduce_add_sub();
                temp.freeze();
                temp.pack(buffer.data() + (i*vole_len + j)*PRIME_BYTES);

                // combine ui into constant term of state
                state[j].coefs[0] += multiplier * ui[i][j];
            }
        }

        co_await chl.send(buffer);

        block seed;
        co_await chl.recv(seed);
        PRNG CheckPrng(seed);
        
        // do consistency check 
        std::vector<fe25519> check_gamma(vole_len-1);
        generateF25519VectorFromSeed(check_gamma, seed);

        buffer.resize((k_vole+1)*PRIME_BYTES);

        // compute cv
        fe25519 cv = state[check_pos].coefs[1];
        for (size_t i = 0; i < vole_len-1; i++)
        {
            cv += check_gamma[i]*state[i].coefs[1];
        }
        cv.reduce_add_sub();
        cv.freeze();
        cv.pack(buffer.data());

        // compute cu_i
        for (size_t i = 0; i < k_vole; i++)
        {
            fe25519 cu_i = (ui[i][check_pos] + dot_product(ui[i],check_gamma));
            cu_i.reduce_add_sub();
            cu_i.freeze();
            cu_i.pack(buffer.data() + (i+1)*PRIME_BYTES);
        }
        
        // send cv and cu_i
        co_await chl.send(buffer);

        co_return;
    }

    task<> prove(const std::vector<fe25519> &gamma, 
                const std::vector<fe25519> &mm, 
                const fe25519 &cu, const fe25519 &cv,
                const std::vector<fe25519> &offsets, 
                const std::vector<unsigned char> &c, 
                PRNG &prng, Socket &chl) 
    {
        // 1. Setup the Random Linear Combination
        block seed;
        co_await chl.recv(seed);
        PRNG LinCombPrng(seed);

        poly<5> check_poly;
        set_zero_poly(check_poly); 
        poly<0> scalar;     

        // =====================================================================
        // BLOCK 1: Constraints C[1] and C[2] (u and v inner products)
        // C[1] = cu - ru - sum(gamma[i] * (K + l_prime[i]) * w[i+v_offset])
        // C[2] = cv - rv - sum(gamma[i] * w[i+v_offset])
        // =====================================================================
        
        // 1. Initialize the accumulators
        poly<1> check_v; set_zero_poly(check_v);
        poly<2> check_u; set_zero_poly(check_u);
        poly<0> gamma_i;

        // 2. Compute the inner products
        for (size_t i = 0; i < leval; i++) 
        {
            gamma_i.coefs[0] = gamma[i];
            
            poly<1> v_i = state[v_offset + i];
            
            poly<1> K_plus_l_prime = state[K_pos];
            K_plus_l_prime.coefs[1] += offsets[i]; // l_prime maps to offsets[0..9]

            // Calculate shared term: gamma[i] * v_i (Degree 1)
            poly<1> gammav = gamma_i * v_i; 
            check_v += gammav; 
            
            // Calculate u term: (gamma[i] * v_i) * (K + l_prime[i]) (Degree 2)
            check_u += gammav * K_plus_l_prime; 
        }

        // Subtract ru, rv with proper shifting
        check_u += shift_up<2, 1>(state[ru_pos]); 
        check_v += state[rv_pos]; 

        // Fold C[1] (No scalar for first one, up to a constant)
        check_poly += shift_up<5, 2>(check_u);
       
        // Fold C[2] 
        random_fe25519(&scalar.coefs[0], LinCombPrng);
        check_poly += shift_up<5, 1>(scalar * check_v);

        // =====================================================================
        // BLOCK 2: Constraints C[3] to C[55] (The b_i evaluations)
        // C[i+2] = mm[i] - w[i+b_offset] * (K + lc_i)
        // =====================================================================
        
        for (size_t i = 0; i < k; i++) 
        {
            poly<1> K_plus_lc = state[K_pos];
            
            K_plus_lc.coefs[1] += offsets[leval + c[i]]; 

            poly<2> b_term = state[b_offset + i] * K_plus_lc;

            random_fe25519(&scalar.coefs[0], LinCombPrng);
            check_poly -= shift_up<5, 2>(scalar * b_term);
        }


        // =====================================================================
        // BLOCK 3: Constraints C[56] and C[57] (c0 and c1 products)
        // C[56] = c0 - v_0 * v_1 * v_2 * v_3 * v_4 
        // C[57] = c1 - v_5 * v_6 * v_7 * v_8 * v_9 
        // =====================================================================

        // Constraint C[56]
        poly<2> v_01   = state[v_offset + 0] * state[v_offset + 1];
        poly<3> v_012  = v_01 * state[v_offset + 2];
        poly<4> v_0123 = v_012 * state[v_offset + 3];
        poly<5> v01234 = v_0123 * state[v_offset + 4]; 
        
        poly<5> check_c0 = shift_up<5, 1>(state[c0_pos]); 
        check_c0 -= v01234;
        reduce_poly(check_c0);

        random_fe25519(&scalar.coefs[0], LinCombPrng);
        check_poly += scalar * check_c0;

        // Constraint C[57]
        poly<2> v_56   = state[v_offset + 5] * state[v_offset + 6];
        poly<3> v_567  = v_56 * state[v_offset + 7];
        poly<4> v_5678 = v_567 * state[v_offset + 8];
        poly<5> v56789 = v_5678 * state[v_offset + 9]; 
        
        poly<5> check_c1 = shift_up<5, 1>(state[c1_pos]);
        check_c1 -= v56789;
        reduce_poly(check_c1);

        random_fe25519(&scalar.coefs[0], LinCombPrng);
        check_poly += scalar * check_c1;
        
        // =====================================================================
        // BLOCK 4: Constraints C[58] to C[65] (The y_i = y_{i-1}^5 checks)
        // C[i+57] = w[i+y_offset] - w[i+y_offset-1]^5
        // =====================================================================
        for (size_t i = 1; i <= 8; i++) 
        {
            // 1. Efficiently compute the 5th power of y_{i-1}
            poly<1> y_prev = state[y_offset + i - 1];
            
            poly<2> y_prev_2 = y_prev * y_prev;          // Degree 2
            poly<4> y_prev_4 = y_prev_2 * y_prev_2;      // Degree 4
            poly<5> y_prev_5 = y_prev_4 * y_prev;        // Degree 5
            
            // 2. Homogenize y_i to Degree 5
            // y_i is degree 1. Shift by (5 - 1) = 4
            poly<5> check_y = shift_up<5, 1>(state[y_offset + i]); 
            
            // 3. Subtract the 5th power to complete the constraint
            check_y -= y_prev_5;
            
            // 4. Fold into master polynomial (No global shift needed)
            random_fe25519(&scalar.coefs[0], LinCombPrng);
            check_poly += scalar * check_y; 
        }

        // =====================================================================
        // BLOCK 5: Constraint C[66] (a0 check)
        // C[66] = a0 - w[y_offset + 8]^2 * w[y_offset + 4] * w[y_offset + 1]^2 
        // =====================================================================
        poly<2> y_8_sq = state[y_offset + 8] * state[y_offset + 8];
        poly<3> y_8_sq_y_4 = y_8_sq * state[y_offset + 4];
        poly<2> y_1_sq = state[y_offset + 1] * state[y_offset + 1];
        
        poly<5> check_a0 = shift_up<5, 1>(state[a0_pos]);
        check_a0 -=  y_8_sq_y_4 * y_1_sq;
        
        random_fe25519(&scalar.coefs[0], LinCombPrng);
        check_poly += scalar * check_a0; 

        // =====================================================================
        // BLOCK 6: Constraint C[67] (a1 check)
        // C[67] = w[y_offset + 1] * a0 - w[y_offset]^2 * w[y_offset + 3] * a1
        // =====================================================================
        poly<2> left_67 = state[y_offset + 1] * state[a0_pos]; 
        
        poly<2> y_0_sq = state[y_offset] * state[y_offset];
        poly<3> y_0_sq_y_3 = y_0_sq * state[y_offset + 3];
        poly<4> right_67 = y_0_sq_y_3 * state[a1_pos];         
        
        poly<4> check_a1 = shift_up<4, 2>(left_67);
        check_a1 -= right_67;
        
        random_fe25519(&scalar.coefs[0], LinCombPrng);
        check_poly += shift_up<5, 4>(scalar * check_a1);

        // =====================================================================
        // BLOCK 7: Constraint C[68] (Final inversion check)
        // C[68] = c0 * c1 * w[y_offset] * a1 - 1
        // =====================================================================
        poly<2> c0_c1 = state[c0_pos] * state[c1_pos];
        
        poly<2> y0_a1 = state[y_offset] * state[a1_pos];
        
        poly<4> check_final = c0_c1 * y0_a1; 
        
        random_fe25519(&scalar.coefs[0], LinCombPrng);
        check_poly += shift_up<5, 4>(scalar * check_final);

        // =====================================================================
        // BLOCK 8: Zero-Knowledge Masking & Network Transfer
        // =====================================================================    
        check_poly += state[mask_pos];                     
        check_poly += shift_up<2, 1>(state[mask_pos + 1]); 
        check_poly += shift_up<3, 1>(state[mask_pos + 2]); 
        check_poly += shift_up<4, 1>(state[mask_pos + 3]); 

        reduce_poly(check_poly);

        // Final step: Send coefficients 0 through 4 to Verifier (coef[5] is 0 if proof is valid)
        std::vector<unsigned char> buffer(5 * PRIME_BYTES);
        for (size_t i = 0; i < 5; i++)
        {
            check_poly.coefs[i].pack(buffer.data() + i * PRIME_BYTES);
        }

        co_await chl.send(buffer);
    }
};


class PROPRF_ZKVerifier
{
public:
    int leval;
    int lcom;
    int k;
    int small_set_bits;
    int statistical_security_bits;
    int k_vole; 
    int vole_len;
    std::vector<fe25519> state;
    fe25519 Delta;

    PROPRF_ZKVerifier(int leval, int lcom, int k, int small_set_bits, int statistical_security_bits) : leval(leval),
                                                                          lcom(lcom),
                                                                          k(k),
                                                                          small_set_bits(small_set_bits),
                                                                          statistical_security_bits(statistical_security_bits)
    {
        k_vole = (statistical_security_bits + small_set_bits - 1)/ small_set_bits;
        vole_len = 4 + leval + k + 12 + 5 + 1; // (4 + leval + k) base witness elements + 12 extra witness elements + 5 masks (A* elements for d=5) + 1 random element (not sure what this is yet)
    };


    task<> commit_to_witness(bool& good, 
        std::vector<std::vector<fe25519>>& oi, 
        std::vector<fe25519>& hi,
        PRNG &prng, 
        Socket &chl) 
    {
        good = true;

        // 1. Process Prover's Derandomization
        // Read the shifted values from the prover to align the VOLE correlation
        std::vector<unsigned char> buffer(k_vole * vole_len * PRIME_BYTES);
        co_await chl.recv(buffer);

        for (size_t i = 0; i < k_vole; i++) {
            for (size_t j = 0; j < vole_len; j++) {
                fe25519 read;
                read.unpack(buffer.data() + (i * vole_len + j) * PRIME_BYTES);
                oi[i][j] += hi[i] * read;
            }
        }

        // 2. Combine Small-Set VOLEs into a single base field VOLE
        // Pack the smaller correlations into the global key (Delta) and the verifier's state (MACs)
        state.resize(vole_len);
        for (size_t i = 0; i < vole_len; i++) {
            state[i].setzero();
        }
        Delta.setzero();

        for (size_t i = 0; i < k_vole; i++) {
            fe25519 multiplier;
            multiplier.setzero();
            
            // Shift the bit dynamically based on the chunk index
            multiplier.v[(i * small_set_bits) / 8] = (1 << ((i * small_set_bits) % 8));
            
            Delta += multiplier * hi[i];
            for (size_t j = 0; j < vole_len; j++) {
                state[j] += multiplier * oi[i][j];
            }
        }

        Delta.reduce_add_sub();
        for (size_t i = 0; i < vole_len; i++) {
            state[i].reduce_add_sub();
        }

        // 3. Global VOLE Consistency Check
        // Send a random challenge seed so the prover can fold all previous VOLEs 
        // into a single linear combination to prove they didn't cheat on the OT extension.
        block seed = prng.get();
        co_await chl.send(seed);
        
        std::vector<fe25519> check_gamma(vole_len - 1);
        generateF25519VectorFromSeed(check_gamma, seed);

        // Receive the folded proof (cv and cu_i)
        buffer.resize((k_vole + 1) * PRIME_BYTES);
        co_await chl.recv(buffer);

        fe25519 cv;
        cv.unpack(buffer.data());

        // Verify the linear combination against our local MACs (oi)
        for (size_t i = 0; i < k_vole; i++) {
            fe25519 check;
            check.unpack(buffer.data() + (1 + i) * PRIME_BYTES);
            
            // Reconstruct the expected MAC and subtract to check for zero
            check += hi[i] * cv;
            check.reduce_add_sub();
            check.neg();
            check += oi[i][check_pos] + dot_product(oi[i], check_gamma);
            check.reduce_add_sub();
            check.freeze();
            
            if (!check.iszero()) {
                good = false;
                co_return;
            }
        }
    }


    task<> verify(bool &valid, 
                  const std::vector<fe25519> &gamma, 
                  const std::vector<fe25519> &mm, 
                  const fe25519 &cu, const fe25519 &cv,
                  const std::vector<fe25519> &offsets, 
                  const std::vector<unsigned char> &c, 
                  PRNG &prng, Socket &chl) 
    {
        valid = false;

        // =====================================================================
        // SETUP: Random Linear Combination & Delta Powers
        // =====================================================================
        // The Verifier generates the seed and sends it to the Prover
        block seed = prng.get();
        co_await chl.send(seed);
        PRNG LinCombPrng(seed);

        // Precompute powers of Delta with explicit reductions
        fe25519 Delta_two = Delta * Delta;
        fe25519 Delta_three = Delta * Delta_two;
        fe25519 Delta_four = Delta_two * Delta_two;
        fe25519 Delta_five = Delta_two * Delta_three;

        // Master accumulator for all folded constraints (evaluating at X = Delta)
        fe25519 check; 
        check.setzero();
        
        // Scalar used to fold constraints
        fe25519 scalar;

        // =====================================================================
        // BLOCK 1: Constraints C[1] and C[2] (u and v inner products)
        // C[1]: cu - ru - sum(gamma[i] * (K + l_prime[i]) * v_i) = 0
        // C[2]: cv - rv - sum(gamma[i] * v_i) = 0
        // =====================================================================
        fe25519 v_check; v_check.setzero();
        fe25519 u_check; u_check.setzero();

        for (size_t i = 0; i < leval; i++)
        {
            fe25519 K_plus_offset = state[K_pos] + (Delta * offsets[i]); // l_prime is offsets[0..9]

            fe25519 gammav = gamma[i] * state[v_offset + i];
            v_check += gammav;
            u_check += gammav * K_plus_offset;
        }

        // Homogenize 
        u_check += Delta * state[ru_pos];
        u_check -= Delta_two * cu;
        u_check *= Delta_three;
 
        v_check += state[rv_pos];
        v_check -= Delta * cv;
        v_check *= Delta_four;

        // Fold C[1] (no random scalar as first one can be one) and C[2] with scalar
        check = u_check;
        
        random_fe25519(&scalar, LinCombPrng);
        check += scalar * v_check;


        // =====================================================================
        // BLOCK 2: Constraints C[3] to C[55] (The b_i evaluations)
        // C[i+2] = mm[i] - w[i+b_offset] * (K + lc_i)
        // =====================================================================
        
        for (size_t i = 0; i < k; i++) 
        {
            fe25519 klci = state[K_pos] + (Delta * offsets[leval + c[i]]);
            fe25519 bi = state[b_offset + i];
            fe25519 check_bi = mm[i] * Delta_two - bi * klci;

            random_fe25519(&scalar, LinCombPrng);
            check += scalar * Delta_three * check_bi;
        }

        
        // =====================================================================
        // BLOCK 3: Constraints C[56] and C[57] (c0 and c1 products)
        // C[56] = c0 - v_0 * v_1 * v_2 * v_3 * v_4 
        // C[57] = c1 - v_5 * v_6 * v_7 * v_8 * v_9 
        // =====================================================================

        // Constraint C[56]
        fe25519 v_01 = state[v_offset + 0] * state[v_offset + 1];
        fe25519 v_012 = v_01 * state[v_offset + 2];
        fe25519 v_0123 = v_012 * state[v_offset + 3];
        fe25519 v01234 = v_0123 * state[v_offset + 4];
        
        fe25519 check_c0 = state[c0_pos] * Delta_four - v01234;
        
        random_fe25519(&scalar, LinCombPrng);
        fe25519 fold_term = scalar * check_c0;
        
        check += fold_term;

        // Constraint C[57]
        fe25519 v_56   = state[v_offset + 5] * state[v_offset + 6];
        fe25519 v_567  = v_56 * state[v_offset + 7];
        fe25519 v_5678 = v_567 * state[v_offset + 8];
        fe25519 v56789 = v_5678 * state[v_offset + 9]; 
        
        fe25519 check_c1 = state[c1_pos] * Delta_four - v56789;

        random_fe25519(&scalar, LinCombPrng);
        check += scalar * check_c1;

        // =====================================================================
        // BLOCK 4: Constraints C[58] to C[65] (The y_i = y_{i-1}^5 checks)
        // C[i+57] = w[i+y_offset] - w[i+y_offset-1]^5
        // =====================================================================
        for (size_t i = 1; i <= 8; i++) 
        {
            // 1. Efficiently compute the 5th power of y_{i-1}
            fe25519 y_prev = state[y_offset + i - 1];
            
            fe25519 y_prev_2 = y_prev * y_prev;          // Degree 2
            fe25519 y_prev_4 = y_prev_2 * y_prev_2;      // Degree 4
            fe25519 y_prev_5 = y_prev_4 * y_prev;        // Degree 5
            
            // 2. Homogenize y_i to Degree 5
            // y_i is degree 1. Shift by (5 - 1) = 4
            fe25519 check_y = state[y_offset + i] * Delta_four; 
            
            // 3. Subtract the 5th power to complete the constraint
            check_y -= y_prev_5;
            
            // 4. Fold into master polynomial 
            random_fe25519(&scalar, LinCombPrng);
            check += scalar * check_y; 
        }

        // =====================================================================
        // BLOCK 5: Constraint C[66] (a0 check)
        // C[66] = a0 - w[y_offset + 8]^2 * w[y_offset + 4] * w[y_offset + 1]^2 
        // =====================================================================
        fe25519 y_8_sq = state[y_offset + 8] * state[y_offset + 8];
        fe25519 y_8_sq_y_4 = y_8_sq * state[y_offset + 4];
        fe25519 y_1_sq = state[y_offset + 1] * state[y_offset + 1];
        
        fe25519 check_a0 = state[a0_pos] * Delta_four;
        check_a0 -= y_8_sq_y_4 * y_1_sq; 
        
        random_fe25519(&scalar, LinCombPrng);
        check += scalar * check_a0; 

        // =====================================================================
        // BLOCK 6: Constraint C[67] (a1 check)
        // C[67] = w[y_offset + 1] * a0 - w[y_offset]^2 * w[y_offset + 3] * a1
        // =====================================================================
        fe25519 left_67 = state[y_offset + 1] * state[a0_pos] * Delta_three; 
        fe25519 right_67 = state[y_offset] * state[y_offset] * state[y_offset + 3] * state[a1_pos] * Delta;         
        
        fe25519 check_a1 = left_67;
        check_a1 -= right_67;
        
        random_fe25519(&scalar, LinCombPrng);
        check += scalar * check_a1;

        // =====================================================================
        // BLOCK 7: Constraint C[68] (Final inversion check)
        // C[68] = c0 * c1 * w[y_offset] * a1 - 1 
        // =====================================================================
        fe25519 check_inv = state[c0_pos] * state[c1_pos] * state[y_offset] * state[a1_pos];
        check_inv -= Delta_four;
        
        random_fe25519(&scalar, LinCombPrng);
        check += scalar * check_inv * Delta; 

        // =====================================================================
        // BLOCK 8: Zero-Knowledge Masking & Final Evaluation
        // =====================================================================
        // Add ZK masks homogenized to Delta powers (Matches Prover's shift_up)
        check += state[mask_pos];
        check += Delta * state[mask_pos + 1];
        check += Delta_two * state[mask_pos + 2];
        check += Delta_three * state[mask_pos + 3];

        // Receive the 5 blinded polynomial coefficients from the Prover
        std::vector<unsigned char> buffer(5 * PRIME_BYTES);
        co_await chl.recv(buffer);

        // Freeze the check accumulator to ensure the debug print shows the canonical reduced value
        check.reduce_add_sub();
        check.freeze();

        // Evaluate the received polynomial at X = Delta using Horner's method
        fe25519 eval;
        eval.unpack(buffer.data() + 4 * PRIME_BYTES); // Start with highest received coefficient (X^4)
        
        for (int i = 3; i >= 0; i--)
        {
            fe25519 read;
            read.unpack(buffer.data() + i * PRIME_BYTES);
            eval = (Delta * eval) + read;
        }

        eval.reduce_add_sub();
        eval.freeze();


        // Final validity check: Prover's evaluated polynomial must match Verifier's MAC accumulator
        eval -= check;
        eval.reduce_add_sub();
        eval.freeze();
        
        valid = eval.iszero();
    }
};

#endif
