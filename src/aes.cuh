// aes.cuh — Phase-6 optimized AES-256 (T-table, big-endian, OpenSSL/hashcat-style).
// Decrypt tables Td0..Td3 (InvMixColumns+InvSubBytes fused) + inv S-box for the last round;
// forward S-box only for key expansion. Tables live in SHARED memory on device (staged once
// per block in kernel.cu). All functions take table pointers so the same code runs on host
// (validation via cuda_stub.h) and device (shared pointers).
//
// Correctness: standard AES-256 on the same key/ciphertext bytes as src/aes_ref.h, so the
// decrypted plaintext bytes are identical -- verified byte-for-byte in the Phase-6 stub test.
#pragma once
#include <cstdint>

namespace mb {

// ---- host-side table generation (fills what kernel.cu uploads) ----
struct AesTd {
    uint32_t Td0[256], Td1[256], Td2[256], Td3[256];
    uint8_t  sbox[256], isbox[256];
};

// GF(2^8) multiply, used only at host table-gen time.
inline uint8_t aes_gmul(uint8_t a, uint8_t b) {
    uint8_t r = 0;
    for (int i = 0; i < 8; i++) { if (b & 1) r ^= a; uint8_t hi = a & 0x80; a <<= 1; if (hi) a ^= 0x1b; b >>= 1; }
    return r;
}
inline void aes_build_tables(AesTd& t) {
    static const uint8_t S[256] = {
        0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
        0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
        0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
        0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
        0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
        0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
        0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
        0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
        0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
        0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
        0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
        0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
        0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
        0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
        0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
        0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16};
    for (int i = 0; i < 256; i++) { t.sbox[i] = S[i]; t.isbox[S[i]] = (uint8_t)i; }
    for (int x = 0; x < 256; x++) {
        uint8_t is = t.isbox[x];
        uint8_t e = aes_gmul(is,14), n = aes_gmul(is,9), d = aes_gmul(is,13), b = aes_gmul(is,11);
        t.Td0[x] = ((uint32_t)e<<24)|((uint32_t)n<<16)|((uint32_t)d<<8)|b;   // [14 9 13 11]
        t.Td1[x] = ((uint32_t)b<<24)|((uint32_t)e<<16)|((uint32_t)n<<8)|d;   // ror8
        t.Td2[x] = ((uint32_t)d<<24)|((uint32_t)b<<16)|((uint32_t)e<<8)|n;   // ror16
        t.Td3[x] = ((uint32_t)n<<24)|((uint32_t)d<<16)|((uint32_t)b<<8)|e;   // ror24
    }
}

// ---- shared/device-callable core (host-callable too, via cuda_stub.h) ----
#if defined(__CUDACC__)
  #define MB_AES_HD __host__ __device__
#else
  #define MB_AES_HD
#endif

MB_AES_HD inline uint32_t aes_getu32_be(const uint8_t* p) {
    return ((uint32_t)p[0]<<24)|((uint32_t)p[1]<<16)|((uint32_t)p[2]<<8)|p[3];
}
MB_AES_HD inline void aes_putu32_be(uint8_t* p, uint32_t v) {
    p[0]=(uint8_t)(v>>24); p[1]=(uint8_t)(v>>16); p[2]=(uint8_t)(v>>8); p[3]=(uint8_t)v;
}
MB_AES_HD inline uint32_t aes_subword(uint32_t w, const uint8_t* S) {
    return ((uint32_t)S[(w>>24)&0xff]<<24)|((uint32_t)S[(w>>16)&0xff]<<16)|
           ((uint32_t)S[(w>>8)&0xff]<<8)|S[w&0xff];
}

// AES-256 decryption key schedule (equivalent inverse cipher). dk holds 60 words.
MB_AES_HD inline void aes256_expand_dec(const uint8_t key[32], uint32_t dk[60],
                                        const uint8_t* S,
                                        const uint32_t* Td0, const uint32_t* Td1,
                                        const uint32_t* Td2, const uint32_t* Td3)
{
    const uint32_t Rcon[7] = {0x01000000,0x02000000,0x04000000,0x08000000,0x10000000,0x20000000,0x40000000};
    uint32_t rk[60];
    for (int i = 0; i < 8; i++) rk[i] = aes_getu32_be(key + 4*i);
    for (int i = 8; i < 60; i++) {
        uint32_t t = rk[i-1];
        if ((i & 7) == 0)      t = aes_subword((t<<8)|(t>>24), S) ^ Rcon[i/8 - 1]; // RotWord+SubWord
        else if ((i & 7) == 4) t = aes_subword(t, S);
        rk[i] = rk[i-8] ^ t;
    }
    // reverse round-key order (Nr=14 -> 15 blocks of 4 words)
    for (int i = 0; i < 60; i += 4) {
        dk[i+0] = rk[56 - i]; dk[i+1] = rk[57 - i]; dk[i+2] = rk[58 - i]; dk[i+3] = rk[59 - i];
    }
    // InvMixColumns on the middle rounds 1..13 (S cancels the inv-S baked into Td => pure IMC)
    for (int r = 1; r <= 13; r++) {
        for (int j = 0; j < 4; j++) {
            uint32_t w = dk[4*r + j];
            dk[4*r + j] = Td0[S[(w>>24)&0xff]] ^ Td1[S[(w>>16)&0xff]] ^ Td2[S[(w>>8)&0xff]] ^ Td3[S[w&0xff]];
        }
    }
}

// AES-256 single-block decrypt (ECB). Nr=14.
MB_AES_HD inline void aes256_decrypt_tt(const uint32_t dk[60], const uint8_t in[16], uint8_t out[16],
                                        const uint32_t* Td0, const uint32_t* Td1,
                                        const uint32_t* Td2, const uint32_t* Td3, const uint8_t* IS)
{
    uint32_t s0 = aes_getu32_be(in+0) ^ dk[0];
    uint32_t s1 = aes_getu32_be(in+4) ^ dk[1];
    uint32_t s2 = aes_getu32_be(in+8) ^ dk[2];
    uint32_t s3 = aes_getu32_be(in+12) ^ dk[3];
    #pragma unroll
    for (int r = 1; r <= 13; r++) {
        uint32_t t0 = Td0[s0>>24] ^ Td1[(s3>>16)&0xff] ^ Td2[(s2>>8)&0xff] ^ Td3[s1&0xff] ^ dk[4*r+0];
        uint32_t t1 = Td0[s1>>24] ^ Td1[(s0>>16)&0xff] ^ Td2[(s3>>8)&0xff] ^ Td3[s2&0xff] ^ dk[4*r+1];
        uint32_t t2 = Td0[s2>>24] ^ Td1[(s1>>16)&0xff] ^ Td2[(s0>>8)&0xff] ^ Td3[s3&0xff] ^ dk[4*r+2];
        uint32_t t3 = Td0[s3>>24] ^ Td1[(s2>>16)&0xff] ^ Td2[(s1>>8)&0xff] ^ Td3[s0&0xff] ^ dk[4*r+3];
        s0=t0; s1=t1; s2=t2; s3=t3;
    }
    // last round: inverse S-box only, no MixColumns
    uint32_t o0 = ((uint32_t)IS[s0>>24]<<24)|((uint32_t)IS[(s3>>16)&0xff]<<16)|((uint32_t)IS[(s2>>8)&0xff]<<8)|IS[s1&0xff];
    uint32_t o1 = ((uint32_t)IS[s1>>24]<<24)|((uint32_t)IS[(s0>>16)&0xff]<<16)|((uint32_t)IS[(s3>>8)&0xff]<<8)|IS[s2&0xff];
    uint32_t o2 = ((uint32_t)IS[s2>>24]<<24)|((uint32_t)IS[(s1>>16)&0xff]<<16)|((uint32_t)IS[(s0>>8)&0xff]<<8)|IS[s3&0xff];
    uint32_t o3 = ((uint32_t)IS[s3>>24]<<24)|((uint32_t)IS[(s2>>16)&0xff]<<16)|((uint32_t)IS[(s1>>8)&0xff]<<8)|IS[s0&0xff];
    aes_putu32_be(out+0,  o0 ^ dk[56]);
    aes_putu32_be(out+4,  o1 ^ dk[57]);
    aes_putu32_be(out+8,  o2 ^ dk[58]);
    aes_putu32_be(out+12, o3 ^ dk[59]);
}

} // namespace mb
