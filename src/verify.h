// verify.h — MultiBit m22500 plaintext-structure predicates.
// Ported 1:1 from hashcat OpenCL/inc_common.cl (is_valid_base58_*) and the m22500 kernels.
#pragma once
#include <cstdint>

// MB_HD makes these predicates usable from both g++ (host) and nvcc (device).
#if defined(__CUDACC__)
  #define MB_HD __host__ __device__
#else
  #define MB_HD
#endif

namespace mb {

// base58 alphabet: 1-9 A-H J-N P-Z a-k m-z   (excludes 0 O I l)
MB_HD inline bool is_valid_base58_8(uint8_t v) {
    if (v > 'z') return false;
    if (v < '1') return false;
    if (v > '9' && v < 'A') return false;
    if (v > 'Z' && v < 'a') return false;
    if (v == 'O' || v == 'I' || v == 'l') return false;
    return true;
}
MB_HD inline bool is_valid_base58_16(const uint8_t b[16]) {
    for (int i = 0; i < 16; i++) if (!is_valid_base58_8(b[i])) return false;
    return true;
}

// bitcoinj tail alphabet: '.' and a-z
MB_HD inline bool is_valid_bitcoinj_8(uint8_t v) {
    if (v > 'z') return false;
    if (v < '.') return false;
    if (v > '.' && v < 'a') return false;
    return true;
}

// The six allowed first bytes of decrypted plaintext block 0.
MB_HD inline bool first_byte_ok(uint8_t b) {
    return b==0x4b || b==0x4c || b==0x51 || b==0x35 || b==0x23 || b==0x0a; // K L Q 5 # \n
}

enum WalletKind { WK_NONE=0, WK_MULTIBIT, WK_BITCOINJ, WK_KNC };

} // namespace mb
