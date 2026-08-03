#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include <iomanip>
#include <cstring>
#include <algorithm>

// Core protocol headers
#include "OPRF.h"
#include "libOTe/Tools/Coproto.h"
#include "coproto/Socket/AsioSocket.h"
#include <cryptoTools/Crypto/PRNG.h>

using namespace osuCrypto;

int main() {
    std::cout << "╔══════════════════════════════════════════════════════════════╗\n";
    std::cout << "║            Post-Quantum OPRF Protocol Interactive CLI        ║\n";
    std::cout << "╚══════════════════════════════════════════════════════════════╝\n\n";

    // ---------------------------------------------------------
    // 1. CLI Prompts
    // ---------------------------------------------------------
    std::string client_input_str;
    std::cout << "[Client] Enter your input string: ";
    std::getline(std::cin, client_input_str);

    std::string server_key_str;
    std::cout << "[Server] Enter server secret key (up to 32 chars): ";
    std::getline(std::cin, server_key_str);

    // Prepare Client Input
    std::vector<char> client_input(client_input_str.begin(), client_input_str.end());

    // Prepare Server Key (Pad or truncate to 32 bytes for fe25519)
    fe25519 server_key;
    server_key.setzero();
    for (size_t i = 0; i < std::min(server_key_str.size(), (size_t)32); ++i) {
        server_key.v[i] = static_cast<uint32_t>(server_key_str[i]);
    }

    std::cout << "\n[*] Initializing protocol parameters...\n";

    // ---------------------------------------------------------
    // 2. Protocol Setup
    // ---------------------------------------------------------
    int len_eval = 10;
    int len_com = 61;
    int k = 53;
    int statistical_sec_bits = 64;
    int small_set_bits = 8;
    
    // Set to true to see the phase-by-phase communication costs!
    bool verbose = true; 

    OPRF oprf(len_eval, len_com, k, statistical_sec_bits, small_set_bits, verbose);
    auto sockets = coproto::LocalAsyncSocket::makePair();

    std::cout << "[*] Starting execution...\n\n";

    // ---------------------------------------------------------
    // 3. Spawn Server Thread
    // ---------------------------------------------------------
    std::thread serverThread([&]() {
        PRNG prng(sysRandomSeed());
        auto proto = oprf.blindedEval(server_key, prng, sockets[1]);
        
        try {
            macoro::sync_wait(std::move(proto));
        } catch (const std::exception& e) {
            // Fails silently here so the main thread can handle the abort cleanly
        }
    });

    // ---------------------------------------------------------
    // 4. Run Client in Main Thread
    // ---------------------------------------------------------
    PRNG prng(sysRandomSeed());
    unsigned char final_output[OPRF_OUTPUT_BYTES];
    
    auto proto = oprf.eval(client_input, final_output, prng, sockets[0]);
    bool success = macoro::sync_wait(std::move(proto));

    // Wait for server to clean up
    serverThread.join();
    
    macoro::sync_wait(sockets[0].flush());
    macoro::sync_wait(sockets[1].flush());

    // ---------------------------------------------------------
    // 5. Output and Summary
    // ---------------------------------------------------------
    if (success) {
        std::cout << "\n╔══════════════════════════════════════════════════════════════╗\n";
        std::cout << "║                OPRF EVALUATION SUCCESSFUL                    ║\n";
        std::cout << "╚══════════════════════════════════════════════════════════════╝\n";
        std::cout << " Client Input : " << client_input_str << "\n";
        
        std::cout << " PRF Output   : ";
        for(int i = 0; i < OPRF_OUTPUT_BYTES; ++i){
            std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)final_output[i];
        }
        std::cout << std::dec << "\n";
    } else {
        std::cout << "\n[!] OPRF EVALUATION FAILED (e.g., ZKP aborted, malicious server detected)\n";
    }

    // Print Final Bandwidth
    double client_sent_kb = sockets[0].bytesSent() / 1024.0;
    double server_sent_kb = sockets[1].bytesSent() / 1024.0;
    
    std::cout << "\n=== Communication Summary ===\n";
    std::cout << std::fixed << std::setprecision(2);
    std::cout << "Sent by client: " << client_sent_kb << " KB\n";
    std::cout << "Sent by server: " << server_sent_kb << " KB\n";
    std::cout << "Total transfer: " << (client_sent_kb + server_sent_kb) << " KB\n";
    std::cout << "=============================\n\n";

    return success ? 0 : 1;
}