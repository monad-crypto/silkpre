/*
   Copyright 2022 The Silkpre Authors

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

#include <benchmark/benchmark.h>

#include <silkpre/precompile.h>

#include "hex.hpp"

#define ECREC 1
#define SHA256 2
#define RIP160 3// precompile 0x03
// precompile 0x4 is the identity function
#define EXPMOD 5
#define BN_ADD 6
#define BN_MUL 7
#define SNARKV 8
#define BLAKE2_F 9

#define PROF ECREC
// #define PROF SHA256
// #define PROF RIP160
// #define PROF EXPMOD
// #define PROF BN_ADD
// #define PROF BN_MUL
// #define PROF SNARKV
// #define PROF BLAKE2_F

#if PROF == ECREC // precompile 0x01
static void prof_ecrec(benchmark::State& state) {
    std::basic_string<uint8_t> in{
        from_hex("18c547e4f7b0f325ad1e56f57e26c745b09a3e503d86e00e5255ff7f715d3d1c0000000000000000000000000000"
                 "00000000000000000000000000000000001c73b1693892219d736caba55bdb67216e485557ea6b6af75f37096c9a"
                 "a6a5a75feeb940b1d03b21e36b0e47e79769f095fe2ab855bd91e3a38756b7d75a9c4549")};
    for (auto _ : state) {
        auto out = silkpre_ecrec_run(in.data(), in.length());
        std::free(out.data);
    }
}

BENCHMARK(prof_ecrec);

#elif PROF == SHA256 // precompile 0x02
static void prof_sha256(benchmark::State& state) {
    std::basic_string<uint8_t> in{
        from_hex("38d18acb67d25c8bb9942764b62f18e17054f66a817bd4295423adf9ed98873e0000000000000000000000000000"
                 "00000000000000000000000000000000001b38d18acb67d25c8bb9942764b62f18e17054f66a817bd4295423adf9"
                 "ed98873e789d1dd423d25f0772d2748d60f7e4b81bb14d086eba8e8e8efb6dcff8a4ae02")};

    for (auto _ : state) {
        SilkpreOutput out{silkpre_sha256_run(in.data(), in.length())};
        std::free(out.data);

    }
}

BENCHMARK(prof_sha256);

#elif PROF == RIP160 // precompile 0x03
static void prof_rip160(benchmark::State& state) {
    std::basic_string<uint8_t> in{
        from_hex("38d18acb67d25c8bb9942764b62f18e17054f66a817bd4295423adf9ed98873e0000000000000000000000000000"
                 "00000000000000000000000000000000001b38d18acb67d25c8bb9942764b62f18e17054f66a817bd4295423adf9"
                 "ed98873e789d1dd423d25f0772d2748d60f7e4b81bb14d086eba8e8e8efb6dcff8a4ae02")};

    for (auto _ : state) {
        SilkpreOutput out{silkpre_rip160_run(in.data(), in.length())};
        std::free(out.data);

    }
}

BENCHMARK(prof_rip160);

// precompile 0x4 is the identity function

#elif PROF == EXPMOD // precompile 0x05
static void prof_expmod(benchmark::State& state) {
    std::basic_string<uint8_t> in{
        from_hex("0000000000000000000000000000000000000000000000000000000000000001"
                 "0000000000000000000000000000000000000000000000000000000000000020"
                 "0000000000000000000000000000000000000000000000000000000000000020"
                 "03"
                 "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2e"
                 "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f")};
    for (auto _ : state) {
        SilkpreOutput out{silkpre_expmod_run(in.data(), in.length())};
        std::free(out.data);

    }
}

BENCHMARK(prof_expmod);

// #define PROF_BN_ADD

#elif PROF == BN_ADD // precompile 0x06
static void prof_bn_add(benchmark::State& state) {
    std::basic_string<uint8_t> in{
        from_hex("00000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000"
                 "00000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000"
                 "000000010000000000000000000000000000000000000000000000000000000000000002")};
    for (auto _ : state) {
        SilkpreOutput out{silkpre_bn_add_run(in.data(), in.length())};
        std::free(out.data);

    }
}

BENCHMARK(prof_bn_add);

// #define PROF_BN_MUL

#elif PROF == BN_MUL // precompile 0x07
static void prof_bn_mul(benchmark::State& state) {
    std::basic_string<uint8_t> in{
        from_hex("1a87b0584ce92f4593d161480614f2989035225609f08058ccfa3d0f940febe31a2f3c951f6dadcc7ee"
                 "9007dff81504b0fcd6d7cf59996efdc33d92bf7f9f8f600000000000000000000000000000000000000"
                 "00000000000000000000000009")};
    for (auto _ : state) {
        SilkpreOutput out{silkpre_bn_mul_run(in.data(), in.length())};
        std::free(out.data);

    }
}

BENCHMARK(prof_bn_mul);

#elif PROF == SNARKV // precompile 0x08
static void prof_snarkv(benchmark::State& state) {
    std::basic_string<uint8_t> in{
        from_hex(
        "0f25929bcb43d5a57391564615c9e70a992b10eafa4db109709649cf48c50dd216da2f5cb6be7a0aa72c440c53c9"
        "bbdfec6c36c7d515536431b3a865468acbba2e89718ad33c8bed92e210e81d1853435399a271913a6520736a4729"
        "cf0d51eb01a9e2ffa2e92599b68e44de5bcf354fa2642bd4f26b259daa6f7ce3ed57aeb314a9a87b789a58af499b"
        "314e13c3d65bede56c07ea2d418d6874857b70763713178fb49a2d6cd347dc58973ff49613a20757d0fcc22079f9"
        "abd10c3baee245901b9e027bd5cfc2cb5db82d4dc9677ac795ec500ecd47deee3b5da006d6d049b811d7511c7815"
        "8de484232fc68daf8a45cf217d1c2fae693ff5871e8752d73b21198e9393920d483a7260bfb731fb5d25f1aa4933"
        "35a9e71297e485b7aef312c21800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed0906"
        "89d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b12c85ea5db8c6deb4aab71808dcb408f"
        "e3d1e7690c43d37b4ce6cc0166fa7daa")};
    for (auto _ : state) {
        SilkpreOutput out{silkpre_snarkv_run(in.data(), in.length())};
        std::free(out.data);

    }
}

BENCHMARK(prof_snarkv);

#elif PROF == BLAKE2_F // precompile 0x09
static void prof_blake2_f(benchmark::State& state) {
    std::basic_string<uint8_t> in{
    from_hex(
        "0000000048c9bdf267e6096a3ba7ca8485ae67bb2bf894fe72f36e3cf1361d5f3af54fa5d182e6ad7f520e511f6c"
        "3e2b8c68059b6bbd41fbabd9831f79217e1319cde05b616263000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000300000000000000000000000000000001")};

    for (auto _ : state) {
        auto out = silkpre_blake2_f_run(in.data(), in.length());
        std::free(out.data);
    }
}

BENCHMARK(prof_blake2_f);
#endif

// precompile 0x0a point evaluation for DENCUN (no support yet)

BENCHMARK_MAIN();
