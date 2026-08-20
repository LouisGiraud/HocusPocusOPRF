# Hocus-Pocus OPRF

This is an implementation the Hocus-Pocus OPRF: A Power Residue Symbol-based Oblivious Pseudorandom Function (OPRF).
It is mostly based on the implementation of the Legendre based 2Hash OPRF Protocol by Beullens et al. [2Hash OPRF](https://eprint.iacr.org/2024/450.pdf)

The goal of this implementation is to prove the concrete efficiency of this approach. It has been tested under Fedora, Ubuntu. Please note that this is an academic proof-of-concept and not an industry-level implementation; there might still be subtle bugs.

## Project Structure

The implementation relies heavily on the [libOTe](https://github.com/osu-crypto/libOTe) library for the Oblivious Transfer protocols and the implementation of the Puncturable PRF (PPRF).

*   `OPRF.h` : Contains the core class that executes the OPRF protocol. 
    *   The `eval` function is executed by the **Client** (takes an input `x` and writes the output to `output`).
    *   The `blindedEval` function is executed by the **Server** (takes the secret `Key` as input and has no output).
*   `main.cpp` : Contains the source code for an interactive CLI implementation to test the protocol locally.
*   `field25519/`: Contains an implementation of finite field arithmetic for the prime field modulo $2^{255}-19$. Partially adapted from [2Hash's implementation](https://github.com/2HashFramework/LegendreOPRF/)
*   `fast_residue_25519.h`: Is an extension of the field25519 library taylored for fast power residue symbol computation without our specific parameters
*   `smallSetVoleFast.h`, `VolePlus.h`, `voleUtils.h`, and `ZKP.h`: The cryptographic building blocks for the OPRF.
    *   `smallSetVoleFast.h`: The small-set VOLE from the [FAEST paper](https://eprint.iacr.org/2023/996.pdf).
    *   `VolePlus.h`: The VOLE+ protocol from Section E of [2Hash paper](https://eprint.iacr.org/2024/450.pdf).
    *   `voleUtils.h`: Helper functions needed for VOLE+.
    *   `ZKP.h`: The implementation of the [Quicksilver](https://eprint.iacr.org/2021/076.pdf) Zero-Knowledge Proof.
*   `tests/`: Contains the test suite.
*   `libOTe/`: Contains commit `0412d31` of the [libOTe library](https://github.com/osu-crypto/libOTe) with a slight modification to run Kyber512 MasRinOT
*   `scripts/`: Contains scripts used for the implementation, checking safety or generating C++ code with Python for fast operations
*   `params-scripts/`: Contains scripts used for the parameter selection



---

## Setup & Installation

#### 1. System Dependencies
To build the code, you need a modern C++ compiler (supporting C++20), Git, Libtool, CMake (min 3.15).

On **Ubuntu**, run:
```bash
sudo apt update
sudo apt install cmake g++ libtool git
```
On **Fedora**, run:
```bash
sudo dnf install cmake gcc-c++ libtool git
```

#### 2. Building libOTe
The project requires a specific vendored version of `libOTe` (commit `0412d31`) where the `KYBER_K` parameter has been modified from 3 to 2 in `thirdparty/KyberOT/params.h` to enable Kyber512 for MasRinOT.

Navigate into the `libOTe` directory and build it:
```bash
cd libOTe
python3 build.py --all --boost --sodium
python3 build.py --sudo --install
```
*(You will be prompted to enter your sudo password for the installation step. If you encounter Position Independent Executable (PIE) errors, add `set(CMAKE_POSITION_INDEPENDENT_CODE ON)` to libOTe's `CMakeLists.txt`).*

#### 3. Building the OPRF Project
Once `libOTe` is installed, return to the root directory of this repository and build the OPRF project:
```bash
mkdir build && cd build
cmake -DCMAKE_BUILD_TYPE=Release ..
cmake --build .
```

---

## Running the Interactive CLI

This repository includes a ready-to-use, interactive command-line interface (CLI) to test the Post-Quantum OPRF functionality locally. 

After building the project, stay in the `build` directory and run:
```bash
./PROPRF
```
When executed, the program will prompt you to enter an arbitrary **client input string** and a **server secret key** (up to 32 characters). It will then execute the full OPRF protocol using two local threads, providing a detailed, phase-by-phase breakdown of the exact communication costs (in bytes) before outputting the final PRF evaluation as a hex string.

---

## Testing & Profiling

You can run the full test suite using `ctest` from within the `build` folder:
```bash
ctest
```
Use `ctest -VV` for a more verbose output.

To run **only** the final OPRF test (which yields the running times reported in the paper), run:
```bash
ctest -R test_OPRF -VV
```

### CPU Clock Speed Configuration (For Reproducible Benchmarks)
To achieve stable and reproducible benchmark timings, you should fix your CPU clock speed by disabling Turbo Boost.

**1. Disable Turbo Boost (locks to base clock, e.g., 1.6 GHz for Core Ultra 5 135U):**
```bash
echo 1 | sudo tee /sys/devices/system/cpu/intel_pstate/no_turbo
```
**2. Re-enable Turbo Boost (returns to dynamic clocking):**
```bash
echo 0 | sudo tee /sys/devices/system/cpu/intel_pstate/no_turbo
```
**3. Monitor live CPU frequencies across all cores to verify:**
```bash
watch -n 1 "grep 'cpu MHz' /proc/cpuinfo"
```

---

## Results

Benchmarks were executed locally on a single machine equipped with an Intel Core Ultra 5 135U processor and 16GB of RAM, running Linux. Both the client and server were executed on the same machine communicating over the local loopback network.

The resulting running times and exact communication costs are as follows:

| `t` | Running Time [ms] | Client Comm. [KB] | Server Comm. [KB] | Total Comm. [KB] |
|:---:|:---:|:---:|:---:|:---:|
| **6**  | 83 | 320.22 | 286.19 | 606.42 |
| **8**  | 99 | 320.22 | 272.05 | 592.27 |
| **10** | 123 | 320.22 | 266.35 | 586.57 |
