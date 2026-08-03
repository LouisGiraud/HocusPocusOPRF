#include "../OPRF.h"
#include <iomanip>

int main(){
        bool correct = false;
        int len_eval = 10;
        int len_com = 61;
        int k = 53;
        int eps = 781764;
        int eps_prime = 781764;
        int statistical_sec_bits = 64;
        bool verbose = false; // If this is true, detailed communication cost is exact and printed but computation artificially slower (full flush)
       
        // parameter t=log|S|, where S is the small set of the underlying VOLE
        int t_values[3] = {6, 8, 10};
        
        for (int small_set_bits : t_values) {
        std::cout << "Bitsize of VOLE set t = " << small_set_bits << std::endl;
        auto sockets = coproto::LocalAsyncSocket::makePair();

        OPRF oprf = OPRF(len_eval,len_com,k,statistical_sec_bits,small_set_bits, verbose);
        std::string str = "hello world";
        std::vector<char> oprf_input(str.begin(), str.end());

TIC
        auto userThread = std::thread([&](){
            PRNG prng(sysRandomSeed());
            unsigned char output[OPRF_OUTPUT_BYTES];
            auto proto = oprf.eval(oprf_input,output,prng,sockets[0]);
            correct = macoro::sync_wait(std::move(proto));

            // Only print the evaluation output if the proof actually passed
            if (correct) {
                std::cout << "evaluation is: ";
                for(int i = 0; i < OPRF_OUTPUT_BYTES; ++i){
                    std::cout << std::hex << std::setw(2) << (int) output[i] << " ";
                }
                std::cout << std::endl;
                std::cout << std::dec;
            }
        });
        
        PRNG prng(sysRandomSeed());
        fe25519 key;
        key.setzero();
        for (size_t i = 0; i < 32; i++)
        {
                key.v[i] = 42;
        }
        auto proto = oprf.blindedEval(key, prng, sockets[1]);
        
        // Wait for the server to finish
        try {
            macoro::sync_wait(std::move(proto));
        } catch (const std::exception& e) {
            // If the client aborted early (co_return false), the socket closes abruptly.
            // Catching this prevents the server thread from crashing the test wrapper.
        }

        userThread.join();
TOC(Total OPRF time)
        std::cout << "Correct: " << std::boolalpha << correct << std::endl;
        
        macoro::sync_wait(sockets[0].flush());
        macoro::sync_wait(sockets[1].flush());
        
        // ╔══════════════════════════════════════════════════════════════════════════╗
        // ║  FINAL COMMUNICATION SUMMARY                                             ║
        // ╚══════════════════════════════════════════════════════════════════════════╝
        double client_sent_kb = sockets[0].bytesSent() / 1024.0;
        double server_sent_kb = sockets[1].bytesSent() / 1024.0;
        
        std::cout << "\n=== Communication Summary ===\n";
        std::cout << std::fixed << std::setprecision(2);
        std::cout << "Sent by client: " << client_sent_kb << " KB\n";
        std::cout << "Sent by server: " << server_sent_kb << " KB\n";
        std::cout << "Total transfer: " << (client_sent_kb + server_sent_kb) << " KB\n";
        std::cout << "=============================\n\n";
        }


}
