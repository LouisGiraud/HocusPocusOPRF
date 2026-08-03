#include <coroutine>
#include <mutex>
#include <sstream>
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
#include "VolePlus.h"
#include "ZKP.h"
#include <cryptoTools/Crypto/Blake2.h>
#include "libOTe/TwoChooseOne/Iknp/IknpOtExtReceiver.h"
#include "libOTe/TwoChooseOne/Iknp/IknpOtExtSender.h"
#include "libOTe/Base/MasnyRindalKyber.h"
#include "fast_residue_25519.h"
#include "field25519/fe25519.h"

using namespace osuCrypto;

// ═══════════════════════════════════════════════════════════════════════════════
// PROFILING MACROS (Thread-Safe, Phase-by-Phase)
// ═══════════════════════════════════════════════════════════════════════════════
inline std::mutex oprf_print_mutex; 

#define INIT_PROFILER \
    uint64_t _s_before = chl.bytesSent(); \
    uint64_t _r_before = chl.bytesReceived();

#define PRINT_PHASE(phase_name) \
    do { \
        if (this->verbose) { \
            coproto::sync_wait(chl.flush()); \
            std::ostringstream _oss; \
            _oss << std::left << std::setw(40) << phase_name \
                 << " Sent: " << (chl.bytesSent() - _s_before) << " B, \t" \
                 << "Recv: " << (chl.bytesReceived() - _r_before) << " B\n"; \
            std::lock_guard<std::mutex> lock(oprf_print_mutex); \
            std::cout << _oss.str(); \
        } \
        _s_before = chl.bytesSent(); \
        _r_before = chl.bytesReceived(); \
    } while(0)


class OPRF
{
public:
    int len_eval;
    int len_com;
    int k;
    int eps;
    int eps_prime;
    int SYMBOL_BYTES_EPS;
    int SYMBOL_BYTES_EPS_PRIME;
    int statistical_security_bits;
    int small_set_bits;
    bool verbose;

    // Offsets is (l',l)
    std::vector<fe25519> offsets;
    int N;
    int repeats;
    VolePlus *volePlus;
    PROPRF_ZKProver *prover;
    PROPRF_ZKVerifier *verifier;
    OtSender *ot_sender;
    OtReceiver *ot_receiver;
    RegularPprfSender<block, CTX> *pprfSender;
    RegularPprfReceiver<block, CTX> *pprfReceiver;
    SmallSetVoleSender25519* ssVoleSenderZKP;
    SmallSetVoleReceiver25519* ssVoleRecZKP;
    SmallSetVoleSender25519* ssVoleSenderVolePlus;
    SmallSetVoleReceiver25519* ssVoleRecVolePlus;
    IknpOtExtSender *otExtSender;
    IknpOtExtReceiver *otExtRecv;

    OPRF(int len_eval, int len_com, int k, int statistical_security_bits, int small_set_bits, bool verbose = false) 
        : len_eval(len_eval),
          len_com(len_com),
          k(k),
          statistical_security_bits(statistical_security_bits),
          small_set_bits(small_set_bits),
          verbose(verbose)
    {
        eps = FastResidue25519::EPS;
        eps_prime = FastResidue25519::EPS_PRIME;
        SYMBOL_BYTES_EPS = FastResidue25519::SYMBOL_BYTES;
        SYMBOL_BYTES_EPS_PRIME = FastResidue25519::SYMBOL_BYTES; // This is fixed on the choice of eps, eps'

        volePlus = new VolePlus(len_eval, small_set_bits, statistical_security_bits);

        prover = new PROPRF_ZKProver(len_eval, len_com,k,small_set_bits, statistical_security_bits); 
        verifier = new PROPRF_ZKVerifier(len_eval, len_com,k,small_set_bits, statistical_security_bits);

        ot_sender = new MasnyRindalKyber();
        ot_receiver = new MasnyRindalKyber();
        otExtSender = new IknpOtExtSender();
        otExtRecv = new IknpOtExtReceiver();

        N = 1 << small_set_bits; // SmallSetSize of the smalSetVole
        repeats = prover->k_vole + volePlus->k_vole; // repeat_ZK + repeat Vole+        
        pprfSender = new RegularPprfSender<block,CTX>(N,repeats);
        pprfReceiver = new RegularPprfReceiver<block,CTX>();
        pprfReceiver->configure(N,repeats);

        ssVoleRecZKP = new SmallSetVoleReceiver25519(verifier->vole_len, small_set_bits, verifier->k_vole);
        ssVoleSenderZKP = new SmallSetVoleSender25519(prover->vole_len, small_set_bits, prover->k_vole);
        ssVoleRecVolePlus = new SmallSetVoleReceiver25519(volePlus->len+1, small_set_bits, volePlus->k_vole);
        ssVoleSenderVolePlus = new SmallSetVoleSender25519(volePlus->len+1, small_set_bits, volePlus->k_vole);
        
        // Compute public parameters l and l' by expanding 0, ensuring no collisions.
        PRNG offset_prng(block(0));
        offsets = std::vector<fe25519>(len_eval + len_com);

        for (size_t i = 0; i < len_com + len_eval; ++i)
        {
            bool collision;
            do {
                collision = false;
                random_fe25519(&offsets[i], offset_prng);
                
                // Check for collisions against all previously generated elements
                for (size_t j = 0; j < i; ++j) {
                    if (offsets[i] == offsets[j]) {
                        collision = true;
                        break;
                    }
                }
            } while (collision);
        }
    };

    
// ═══════════════════════════════════════════════════════════════════════════════
//  Client::eval( x, output, prng, chl )
//  Implements the Client's side of Figure 3 (Optimized Protocol).
//  x      → input to the OPRF (will be slow‑hashed to h)
//  output → final PRF value (after H₂)
// ═══════════════════════════════════════════════════════════════════════════════

task<bool> eval(
    std::vector<char> &x,
    unsigned char *output,
    PRNG &prng,
    Socket &chl)
{
    INIT_PROFILER; // Start tracking bytes

    // ╔══════════════════════════════════════════════════════════════════════════╗
    // ║  PHASE 0: HASH INPUT x → h   (H₁ with 2¹⁶ iterations)                    ║
    // ║  h ← H₁(x)  (slow hash to prevent brute‑force)                           ║
    // ╚══════════════════════════════════════════════════════════════════════════╝

    fe25519 h;
    Blake2 hash_one(PRIME_BYTES);
    unsigned char hashed[PRIME_BYTES];
    hash_one.Update(x.data(), x.size());
    hash_one.Final(hashed);

    for (size_t i = 0; i < (1 << 16); ++i) {
        Blake2 hash_repeated(PRIME_BYTES);
        hashed[0] ^= i;
        hashed[1] ^= i / 256;
        hash_repeated.Update(hashed, PRIME_BYTES);
        hash_repeated.Final(hashed);
    }
    h.unpack(hashed);

    // Allocate buffer for the final transcript (will be hashed with H₂)
    std::vector<unsigned char> transcript;
    transcript.reserve((len_com * SYMBOL_BYTES_EPS) +
                       (len_eval * SYMBOL_BYTES_EPS_PRIME) +
                       x.size());


    // ╔══════════════════════════════════════════════════════════════════════════╗
    // ║  PHASE 1: PREPROCESSING — Generate VOLE correlations                     ║
    // ║  (Abstracts away OT/PPRF; outputs sVOLE for VOLE+ and ZK)                ║
    // ╚══════════════════════════════════════════════════════════════════════════╝

    // ── 1.1 Base Oblivious Transfers (Masny‑Rindal Kyber) ──
    AlignedUnVector<std::array<block, 2>> baseSend(NUM_BASE_OT);
    auto base_ot_proto = ot_sender->send(baseSend, prng, chl);
    coproto::sync_wait(macoro::wrap(base_ot_proto));

    // ── 1.2 OT Extension (IKNP) ──
    otExtRecv->mHashType = HashType::AesHash;
    int numOTs = pprfReceiver->baseOtCount();
    otExtRecv->setBaseOts(baseSend);
    std::vector<block> recvOTs(numOTs);
    BitVector recvBits = pprfReceiver->sampleChoiceBits(prng);
    auto ot_ext_proto = otExtRecv->receive(recvBits, recvOTs, prng, chl);
    coproto::sync_wait(macoro::wrap(ot_ext_proto));

    // ── 1.3 PPRF Expansion (N-1‑out‑of‑N OT) ──
    pprfReceiver->setBase(recvOTs);
    Vec a(N * repeats);
    std::vector<u64> points(repeats);
    pprfReceiver->getPoints(points, FORMAT);
    coproto::sync_wait(macoro::wrap(pprfReceiver->expand(chl, a, FORMAT, false, 1)));

    // ── 1.4 Small‑Set VOLE (split into two buckets) ──
    std::vector<std::vector<fe25519>> oi_vole;
    std::vector<fe25519> hi_vole;
    auto vole_proto = ssVoleRecVolePlus->receive(oi_vole, hi_vole, a, verifier->k_vole, points, prng, chl);
    coproto::sync_wait(macoro::wrap(vole_proto));

    std::vector<std::vector<fe25519>> oi_zkp;
    std::vector<fe25519> hi_zkp;
    auto sszkp_proto = ssVoleRecZKP->receive(oi_zkp, hi_zkp, a, 0, points, prng, chl);
    coproto::sync_wait(macoro::wrap(sszkp_proto));

    PRINT_PHASE("[Client] Phase 1 (Preprocessing)");


    // ╔══════════════════════════════════════════════════════════════════════════╗
    // ║  PHASE 2: SETUP ZERO‑KNOWLEDGE PROOF (Verifier side)                     ║
    // ║  (Arrow to "Committed" in Figure 3)                                      ║
    // ║  The server has committed its witness w via sVOLE;                       ║
    // ║  we now reconstruct our keys and check VOLE consistency.                 ║
    // ╚══════════════════════════════════════════════════════════════════════════╝

    bool good;
    auto proto_wit = verifier->commit_to_witness(good, oi_zkp, hi_zkp, prng, chl);
    coproto::sync_wait(proto_wit);

    if (!good) {
        std::cout << "Abort: Server cheated in ZK commitment phase." << std::endl;
        co_return false;
    }

    PRINT_PHASE("[Client] Phase 2 (ZK Setup)");


    // ╔══════════════════════════════════════════════════════════════════════════╗
    // ║  PHASE 3: RUN VOLE+ (Receive linear OPRF computation)                    ║
    // ║  Input:  h (hashed client input)                                         ║
    // ║  Output: o = u + h·v,  γ,  c_u,  c_v                                     ║
    // ║  (Matches the "o, γ, c_u, c_v" arrow in Figure 3)                        ║
    // ╚══════════════════════════════════════════════════════════════════════════╝

    std::vector<fe25519> o;
    std::vector<fe25519> gamma;
    fe25519 cu, cv;
    auto plus_proto = volePlus->receive(h, o, gamma, cu, cv, oi_vole, hi_vole, prng, chl);
    coproto::sync_wait(macoro::wrap(plus_proto));

    PRINT_PHASE("[Client] Phase 3 (VOLE+ Eval)");


    // ╔══════════════════════════════════════════════════════════════════════════╗
    // ║  PHASE 4: RECEIVE e FROM SERVER (arrow "e" in Figure 3)                  ║
    // ║  Abort if e_i = 0 for any i ∈ [ℓ_com]                                    ║
    // ╚══════════════════════════════════════════════════════════════════════════╝

    std::vector<unsigned char> buffer(len_com * SYMBOL_BYTES_EPS);
    coproto::sync_wait(chl.recv(buffer));

    std::vector<uint32_t> e(len_com);
    for (size_t i = 0; i < len_com; ++i) {
        e[i] = FastResidue25519::unpack(&buffer[i * SYMBOL_BYTES_EPS]);
    }

    for (size_t i = 0; i < len_com; ++i) {
        if (e[i] == 0) {
            std::cout << "Abort: e_i = 0 detected." << std::endl;
            co_return false;
        }
    }

    PRINT_PHASE("[Client] Phase 4 (Recv e)");


    // ╔══════════════════════════════════════════════════════════════════════════╗
    // ║  PHASE 5: DRAW CHALLENGE c AND SEND TO SERVER (arrow "c" in Fig. 3)      ║
    // ║  c ← distinct indices from [ℓ_com]^k                                     ║
    // ╚══════════════════════════════════════════════════════════════════════════╝

    std::vector<uint32_t> c;
    c.reserve(k);
    while (c.size() < k) {
        uint32_t idx = prng.get<uint32_t>() % len_com;
        if (std::find(c.begin(), c.end(), idx) == c.end()) {
            c.push_back(idx);
        }
    }

    std::vector<unsigned char> c_buf(k);
    for (size_t i = 0; i < k; ++i) {
        c_buf[i] = static_cast<unsigned char>(c[i]);
    }
    coproto::sync_wait(chl.send(c_buf));

    PRINT_PHASE("[Client] Phase 5 (Send c)");


    // ╔══════════════════════════════════════════════════════════════════════════╗
    // ║  PHASE 6: RECEIVE m FROM SERVER AND VERIFY (arrow "m" in Fig. 3)         ║
    // ║  Abort if (m_i / p)_ε ≠ e_{c_i}  for any i ∈ [k]                         ║
    // ║  (This ensures m_i is a valid preimage of the challenged e symbol)       ║
    // ╚══════════════════════════════════════════════════════════════════════════╝

    std::vector<unsigned char> m_buf(k * PRIME_BYTES);
    coproto::sync_wait(chl.recv(m_buf));

    std::vector<fe25519> m(k);
    for (size_t i = 0; i < k; ++i) {
        m[i].unpack(m_buf.data() + i * PRIME_BYTES);
    }

    for (size_t i = 0; i < k; ++i) {
        if (FastResidue25519::presidue_eps(m[i]) != e[c[i]]) {
            std::cout << "Abort: (m_i/p)_ε != e_{c_i}" << std::endl;
            co_return false;
        }
    }

    PRINT_PHASE("[Client] Phase 6 (Recv m)");


    // ╔══════════════════════════════════════════════════════════════════════════╗
    // ║  PHASE 7: VERIFY ZERO‑KNOWLEDGE PROOF (arrow to F_ZK)                    ║
    // ║  Checks all constraints:                                                 ║
    // ║    f_u, f_v, f_b^(i), f_a (see "Both parties locally compute F")         ║
    // ╚══════════════════════════════════════════════════════════════════════════╝

    bool valid;
    auto proto_vfy = verifier->verify(valid, gamma, m, cu, cv, offsets, c_buf, prng, chl);
    coproto::sync_wait(macoro::wrap(proto_vfy));

    if (!valid) {
        std::cout << "Abort: ZK Proof verification failed." << std::endl;
        co_return false;
    }

    PRINT_PHASE("[Client] Phase 7 (ZK Verify)");


    // ╔══════════════════════════════════════════════════════════════════════════╗
    // ║  PHASE 8: FINALISE OPRF OUTPUT (bottom of Figure 3)                      ║
    // ║  • Serialize e (public symbols)                                          ║
    // ║  • Compute e' from o:  e'_i ← (o_i / p)_{ε'}                             ║
    // ║  • Append raw input x                                                    ║
    // ║  • Apply second hash H₂ to get final PRF value                           ║
    // ╚══════════════════════════════════════════════════════════════════════════╝

    unsigned char sym_buf[4];  // Max 4 bytes for safety

    // 8.1 Serialise e
    for (size_t i = 0; i < len_com; ++i) {
        FastResidue25519::pack(sym_buf, e[i]);
        transcript.insert(transcript.end(), sym_buf, sym_buf + SYMBOL_BYTES_EPS);
    }

    // 8.2 Compute and serialise e' = (o_i / p)_{ε'}
    for (size_t i = 0; i < len_eval; ++i) {
        uint32_t sym_prime = FastResidue25519::presidue_eps_prime(o[i]);
        FastResidue25519::pack(sym_buf, sym_prime);
        transcript.insert(transcript.end(), sym_buf, sym_buf + SYMBOL_BYTES_EPS_PRIME);
    }

    // 8.3 Append raw input x
    transcript.insert(transcript.end(), x.begin(), x.end());

    // 8.4 Final hash:  output ← H₂(transcript)
    Blake2 hash_two(OPRF_OUTPUT_BYTES);
    hash_two.Update(transcript.data(), transcript.size());
    hash_two.Final(output);

    co_return true;
}



// ═══════════════════════════════════════════════════════════════════════════════
//  Server::blindedEval( Key, prng, chl )
//  Implements the Server's side of Figure 3.
// ═══════════════════════════════════════════════════════════════════════════════

task<> blindedEval(
    fe25519 Key,
    PRNG &prng,
    Socket &chl)
    {
        INIT_PROFILER;

        // ╔══════════════════════════════════════════════════════════════════════════╗
        // ║  PHASE 0: PREPROCESSING — Generate VOLE correlations                     ║
        // ║  (Abstracts away OT/PPRF; outputs sVOLE for VOLE+ and ZK)                ║
        // ╚══════════════════════════════════════════════════════════════════════════╝

        // ── 0.1 Base Oblivious Transfers (Masny‑Rindal Kyber) ──
        AlignedUnVector<block> baseRecv(NUM_BASE_OT);
        BitVector baseChoice(NUM_BASE_OT);
        baseChoice.randomize(prng);
        auto base_ot_proto = ot_receiver->receive(baseChoice, baseRecv, prng, chl);
        coproto::sync_wait(macoro::wrap(base_ot_proto));

        // ── 0.2 OT Extension (IKNP) ──
        otExtSender->mHashType = HashType::AesHash;
        int numOTs = pprfSender->baseOtCount();
        otExtSender->setBaseOts(baseRecv, baseChoice);
        std::vector<std::array<block, 2>> sendOTs(numOTs);
        auto ot_ext_proto = otExtSender->send(sendOTs, prng, chl);
        coproto::sync_wait(macoro::wrap(ot_ext_proto));

        // ── 0.3 PPRF Expansion (N-1‑out‑of‑N OT) ──
        pprfSender->setBase(sendOTs);
        Vec b_ot(N * repeats);
        coproto::sync_wait(macoro::wrap(
            pprfSender->expand(chl, 0, prng.get(), b_ot, FORMAT, false, 1)
        ));

        // ── 0.4 Small‑Set VOLE (split into two buckets) ──
        std::vector<std::vector<fe25519>> ui_vole, vi_vole;
        auto vole_proto = ssVoleSenderVolePlus->send(ui_vole, vi_vole, b_ot, prover->k_vole, prng, chl);
        coproto::sync_wait(macoro::wrap(vole_proto));

        std::vector<std::vector<fe25519>> ui_zkp, vi_zkp;
        auto sszkp_proto = ssVoleSenderZKP->send(ui_zkp, vi_zkp, b_ot, 0, prng, chl);
        coproto::sync_wait(macoro::wrap(sszkp_proto));

        PRINT_PHASE("[Server] Phase 0 (Preprocessing)");


        // ╔══════════════════════════════════════════════════════════════════════════╗
        // ║  PHASE 1: GENERATE WITNESS (Server block in Figure 3)                    ║
        // ║  v ← ((F_p^×)^ℓ)^ε_eval,  u ← (K·1 + l') * v,                            ║
        // ║  r_u, r_v ← F_p,  e ← {(K+l_i)/p}_ε,  b ← (F_p^×)^k,                     ║
        // ║  a ← (∏ v_i)^(-1/ε')                                                     ║
        // ║  y_i ← y_{i-1}^5 (with y_0 = a), i ∈ [1, 8]                              ║
        // ║  a_0 ← y_8^2 · y_4 · y_1^2, a_1 ← y_1 / (a^2 · y_3)                      ║
        // ║  c_0 ← ∏_{i=0}^4 v_i, c_1 ← ∏_{i=5}^9 v_i                               ║
        // ╚══════════════════════════════════════════════════════════════════════════╝

        // Abort if the key collides with any offset (K ∉ L)
        for (size_t i = 0; i < len_com + len_eval; ++i) {
            if (Key == offsets[i]) {
                std::cout << "Abort: Key collides with an offset." << std::endl;
                co_return;
            }
        }

        std::vector<fe25519> v(len_eval);
        std::vector<fe25519> u(len_eval);
        std::vector<fe25519> b(k);
        fe25519 ru, rv, a;
        std::vector<fe25519> y(8);
        fe25519 c0, c1, a0, a1;
        a.setone();

        for (size_t i = 0; i < len_eval; ++i) {
            v[i] = FastResidue25519::random_power_eps_prime(prng);
            u[i] = (Key + offsets[i]);
            u[i].reduce_add_sub();
            u[i] *= v[i];
            a *= v[i];
        }

        a = FastResidue25519::pow_inv_eps_prime(a);

        random_fe25519(&ru, prng);
        random_fe25519(&rv, prng);
        for (size_t i = 0; i < k; ++i) {
            b[i] = FastResidue25519::random_power_eps(prng);
        }

        std::vector<uint32_t> e(len_com);
        fe25519 Kli;
        for (size_t i = 0; i < len_com; ++i) {
            Kli = Key + offsets[i + len_eval];
            e[i] = FastResidue25519::presidue_eps(Kli);
        }

        fe25519 prev = a;
        for (size_t i = 0; i < 8; ++i) {
            prev = pow5(prev);
            y[i] = prev;
        }

        a0 = (y[7] * y[7]) * y[3] * y[0] * y[0];
        a1 = (y[0] * a0) / (a * a * y[2]); 
        
        c0.setone();
        c1.setone();
        for (size_t i = 0; i < 5; ++i){
            c0 *= v[i];
            c1 *= v[i+5];
        }


        // ╔══════════════════════════════════════════════════════════════════════════╗
        // ║  PHASE 2: COMMIT WITNESS TO F_ZK (arrow to "Committed" in Figure 3)      ║
        // ║  w ← (K, v, b, r_u, r_v, a, y1, ..., y8, a0, a1, c0, c1)                 ║
        // ╚══════════════════════════════════════════════════════════════════════════╝

        std::vector<fe25519> w;
        w.reserve(79);
        w.push_back(Key);
        w.insert(w.end(), v.begin(), v.end());
        w.insert(w.end(), b.begin(), b.end());
        w.push_back(ru);
        w.push_back(rv);
        w.push_back(a);
        w.insert(w.end(), y.begin(), y.end());
        w.push_back(a0);
        w.push_back(a1);
        w.push_back(c0);
        w.push_back(c1);

        auto wit_proto = prover->commit_to_witness(w, ui_zkp, vi_zkp, prng, chl);
        coproto::sync_wait(macoro::wrap(wit_proto));

        PRINT_PHASE("[Server] Phase 1-2 (Gen & Commit Witness)");


        // ╔══════════════════════════════════════════════════════════════════════════╗
        // ║  PHASE 3: SEND (u, v, r_u, r_v) TO F_VOLE+  (gets γ back)                ║
        // ╚══════════════════════════════════════════════════════════════════════════╝

        std::vector<fe25519> gamma;
        auto plus_proto = volePlus->send(u, v, ru, rv, gamma, ui_vole, vi_vole, prng, chl);
        coproto::sync_wait(macoro::wrap(plus_proto));

        PRINT_PHASE("[Server] Phase 3 (VOLE+ Eval)");


        // ╔══════════════════════════════════════════════════════════════════════════╗
        // ║  PHASE 4: SEND e TO CLIENT (arrow "e" in Figure 3)                       ║
        // ╚══════════════════════════════════════════════════════════════════════════╝

        std::vector<unsigned char> packed_e(len_com * SYMBOL_BYTES_EPS);
        for (size_t i = 0; i < len_com; ++i) {
            FastResidue25519::pack(&packed_e[i * SYMBOL_BYTES_EPS], e[i]);
        }
        coproto::sync_wait(chl.send(packed_e));

        PRINT_PHASE("[Server] Phase 4 (Send e)");


        // ╔══════════════════════════════════════════════════════════════════════════╗
        // ║  PHASE 5: RECEIVE CHALLENGE c FROM CLIENT (arrow "c" in Figure 3)        ║
        // ╚══════════════════════════════════════════════════════════════════════════╝

        std::vector<unsigned char> c(k);
        coproto::sync_wait(chl.recv(c));

        PRINT_PHASE("[Server] Phase 5 (Recv c)");


        // ╔══════════════════════════════════════════════════════════════════════════╗
        // ║  PHASE 6: COMPUTE m AND SEND TO CLIENT (arrow "m" in Figure 3)           ║
        // ║  m_i ← b_i · (K + l_{c_i})  ∀ i ∈ [k]                                    ║
        // ╚══════════════════════════════════════════════════════════════════════════╝

        std::vector<fe25519> m(k);
        for (size_t i = 0; i < k; ++i) {
            fe25519 lci = offsets[len_eval + c[i]];      // l_{c_i} is in the second half of offsets
            m[i] = b[i] * (Key + lci);
        }

        std::vector<unsigned char> m_buf(k * PRIME_BYTES);
        for (size_t i = 0; i < k; ++i) {
            m[i].pack(m_buf.data() + i * PRIME_BYTES);
        }
        coproto::sync_wait(chl.send(m_buf));

        PRINT_PHASE("[Server] Phase 6 (Send m)");


        // ╔══════════════════════════════════════════════════════════════════════════╗
        // ║  PHASE 7: LOCALLY COMPUTE c_u, c_v  (bottom of Figure 3)                 ║
        // ║  c_u = r_u + ⟨γ, u⟩ ,  c_v = r_v + ⟨γ, v⟩                                ║
        // ╚══════════════════════════════════════════════════════════════════════════╝

        fe25519 cu = ru;
        fe25519 cv = rv;
        for (size_t i = 0; i < len_eval; ++i) {
            cu += gamma[i] * u[i];
            cv += gamma[i] * v[i];
        }


        // ╔══════════════════════════════════════════════════════════════════════════╗
        // ║  PHASE 8: EXECUTE ZERO-KNOWLEDGE PROOF (arrow to F_ZK)                   ║
        // ║  Proves all constraints:                                                 ║ 
        // ║    f_u, f_v, f_b^(i), f_a  (see "Both parties locally compute F")        ║
        // ╚══════════════════════════════════════════════════════════════════════════╝

        auto proto_prove = prover->prove(gamma, m, cu, cv, offsets, c, prng, chl);
        coproto::sync_wait(macoro::wrap(proto_prove));

        PRINT_PHASE("[Server] Phase 7-8 (ZK Prove)");

        co_return;
    }
};