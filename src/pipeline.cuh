// pipeline.cuh — device per-candidate pipeline (Phase 6: T-table AES).
// Two entry points share ONE body via a small context struct so the amplifier kernel can
// hoist key1's MD5 message assembly while staying bit-identical to the reference path:
//   * dev_try_password   : self-contained (used for stub validation) -- builds everything.
//   * dev_finish_from_key1: takes a precomputed key1 digest (kernel inner loop) -- identical math.
// Both reproduce src/pipeline_ref.h (the g++-validated CPU reference) exactly.
#pragma once
#include <cstdint>
#include "verify.h"
#include "md5.cuh"
#include "aes.cuh"

namespace mb {

// Shared-memory AES table pointers, bundled to keep signatures short.
struct AesShared {
    const uint32_t *Td0, *Td1, *Td2, *Td3;
    const uint32_t *IMC0, *IMC1, *IMC2, *IMC3;   // P1: InvMixColumns key-schedule tables
    const uint8_t  *sbox, *isbox;
};

// Given key1 (16 bytes) already computed, finish the pipeline. Returns WalletKind.
__device__ inline int dev_finish_from_key1(const uint8_t d1[16],
                                           const uint8_t* salt, const uint8_t* data,
                                           const uint8_t* pw, int pw_len,
                                           const AesShared& tb, uint32_t lane = 0)
{
    uint8_t d2[16], iv[16];
    d_md5(d1, 16, pw, pw_len, salt, 8, d2);   // key2 = MD5(key1 || pw || salt)
    d_md5(d2, 16, pw, pw_len, salt, 8, iv);   // iv   = MD5(key2 || pw || salt)

    uint8_t key[32];
    #pragma unroll
    for (int i = 0; i < 16; i++) { key[i] = d1[i]; key[16+i] = d2[i]; }

    uint32_t dk[60];
    aes256_expand_dec(key, dk, tb.sbox, tb.IMC0, tb.IMC1, tb.IMC2, tb.IMC3);

    // Diffuse the first ciphertext block through the 13 middle rounds, then reject on the CBC
    // first plaintext byte alone (~253/256 candidates die here) BEFORE computing the full final
    // round + 16-byte IV XOR. b == p0[0] exactly (final byte0 ^ iv[0]).
    uint32_t st0, st1, st2, st3;
#ifdef MB_BANK_PIN
    aes256_decrypt_rounds_pin(dk, data, st0, st1, st2, st3, tb.Td0, lane);   // conflict-free Td0
#else
    aes256_decrypt_rounds(dk, data, st0, st1, st2, st3, tb.Td0, tb.Td1, tb.Td2, tb.Td3);
#endif
    uint8_t b = aes256_decrypt_byte0(dk, st0, tb.isbox) ^ iv[0];

#ifdef MB_WALLET_MULTIBIT
    // Single-wallet build (-DMB_WALLET_MULTIBIT): only the 4 MultiBit-Classic magic first bytes
    // survive; the bitcoinj/KnC branches are compiled out (tighter 4/256 reject + one straight-line
    // survivor path -> fewer live registers, so the kernel fits 2 blocks/SM). The AES math and the
    // MultiBit verdict stay bit-identical to the multi-type build for any MultiBit wallet; this build
    // simply does not detect the other two kinds. Composes with MB_BANK_PIN[_FULL] (pinned decrypt).
    if (!(b==0x4b || b==0x4c || b==0x51 || b==0x35)) return WK_NONE;

    uint8_t p0[16];
    aes256_decrypt_final(dk, st0, st1, st2, st3, p0, tb.isbox);
    #pragma unroll
    for (int i = 0; i < 16; i++) p0[i] ^= iv[i];
    if (!is_valid_base58_16(p0)) return WK_NONE;

    uint8_t p1[16];
#ifdef MB_BANK_PIN
    aes256_decrypt_tt_pin(dk, data + 16, p1, tb.Td0, lane, tb.isbox);
#else
    aes256_decrypt_tt(dk, data + 16, p1, tb.Td0, tb.Td1, tb.Td2, tb.Td3, tb.isbox);
#endif
    #pragma unroll
    for (int i = 0; i < 16; i++) p1[i] ^= data[i];
    if (!is_valid_base58_16(p1)) return WK_NONE;
    return WK_MULTIBIT;
#else
    if (!first_byte_ok(b)) return WK_NONE;

    // Survivor: complete the block (final round + CBC IV XOR).
    uint8_t p0[16];
    aes256_decrypt_final(dk, st0, st1, st2, st3, p0, tb.isbox);
    #pragma unroll
    for (int i = 0; i < 16; i++) p0[i] ^= iv[i];

    if (b==0x4b || b==0x4c || b==0x51 || b==0x35) {
        if (!is_valid_base58_16(p0)) return WK_NONE;
        uint8_t p1[16];
#ifdef MB_BANK_PIN
        aes256_decrypt_tt_pin(dk, data + 16, p1, tb.Td0, lane, tb.isbox);
#else
        aes256_decrypt_tt(dk, data + 16, p1, tb.Td0, tb.Td1, tb.Td2, tb.Td3, tb.isbox);
#endif
        #pragma unroll
        for (int i = 0; i < 16; i++) p1[i] ^= data[i];
        if (!is_valid_base58_16(p1)) return WK_NONE;
        return WK_MULTIBIT;
    } else if (b == 0x0a) {
        if (p0[1] > 0x7f) return WK_NONE;
        if (p0[2]!='o'||p0[3]!='r'||p0[4]!='g'||p0[5]!='.') return WK_NONE;
        #pragma unroll
        for (int i = 6; i <= 13; i++) if (!is_valid_bitcoinj_8(p0[i])) return WK_NONE;
        return WK_BITCOINJ;
    } else {
        const char* s0 = "# KEEP YOUR PRIV";
        #pragma unroll
        for (int i = 0; i < 16; i++) if (p0[i] != (uint8_t)s0[i]) return WK_NONE;
        uint8_t p1[16];
#ifdef MB_BANK_PIN
        aes256_decrypt_tt_pin(dk, data + 16, p1, tb.Td0, lane, tb.isbox);
#else
        aes256_decrypt_tt(dk, data + 16, p1, tb.Td0, tb.Td1, tb.Td2, tb.Td3, tb.isbox);
#endif
        #pragma unroll
        for (int i = 0; i < 16; i++) p1[i] ^= data[i];
        const char* s1 = "ATE KEYS SAFE! A";
        #pragma unroll
        for (int i = 0; i < 16; i++) if (p1[i] != (uint8_t)s1[i]) return WK_NONE;
        return WK_KNC;
    }
#endif
}

// Self-contained variant (builds key1 too). Used by the correctness stub test.
__device__ inline int dev_try_password(const uint8_t* salt, const uint8_t* data,
                                       const uint8_t* pw, int pw_len, const AesShared& tb, uint32_t lane = 0)
{
    uint8_t d1[16];
    d_md5(pw, pw_len, salt, 8, nullptr, 0, d1);   // key1 = MD5(pw || salt)
    return dev_finish_from_key1(d1, salt, data, pw, pw_len, tb, lane);
}

} // namespace mb
