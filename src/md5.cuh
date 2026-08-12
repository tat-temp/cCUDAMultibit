// md5.cuh — device MD5 for m22500. Single 64-byte block only (pw_len<=31 => every KDF
// message is <=55 bytes => always one block). Split into buildM + compress so the amplifier
// kernel can hoist the message assembly for key1 out of the inner charset loop (only w[0]
// varies with the fastest password position). See DEVELOPMENT_PLAN.md §2.2.
#pragma once
#include <cstdint>

#if defined(__CUDACC__)
  #define MB_MD5_HD __host__ __device__
#else
  #define MB_MD5_HD
#endif

namespace mb {

MB_MD5_HD __forceinline__ uint32_t drotl(uint32_t x, int c) { return (x << c) | (x >> (32 - c)); }

// Build the padded single-block message words for MD5(a||b||c). total len MUST be <= 55.
MB_MD5_HD inline void d_md5_buildM(const uint8_t* a, int la,
                                   const uint8_t* b, int lb,
                                   const uint8_t* c, int lc,
                                   uint32_t M[16])
{
    uint8_t msg[64];
    #pragma unroll
    for (int i = 0; i < 64; i++) msg[i] = 0;
    int p = 0;
    for (int i = 0; i < la; i++) msg[p++] = a[i];
    for (int i = 0; i < lb; i++) msg[p++] = b[i];
    for (int i = 0; i < lc; i++) msg[p++] = c[i];
    msg[p] = 0x80;
    uint32_t bits = (uint32_t)(la + lb + lc) * 8u;
    msg[56] = (uint8_t)bits; msg[57] = (uint8_t)(bits>>8); msg[58] = (uint8_t)(bits>>16); msg[59] = (uint8_t)(bits>>24);
    #pragma unroll
    for (int i = 0; i < 16; i++)
        M[i] = (uint32_t)msg[i*4] | ((uint32_t)msg[i*4+1]<<8) | ((uint32_t)msg[i*4+2]<<16) | ((uint32_t)msg[i*4+3]<<24);
}

// Full MD5 compression of one prepared block. out = 16-byte little-endian digest.
MB_MD5_HD inline void d_md5_compress(const uint32_t M[16], uint8_t out[16])
{
    const uint32_t K[64] = {
        0xd76aa478,0xe8c7b756,0x242070db,0xc1bdceee,0xf57c0faf,0x4787c62a,0xa8304613,0xfd469501,
        0x698098d8,0x8b44f7af,0xffff5bb1,0x895cd7be,0x6b901122,0xfd987193,0xa679438e,0x49b40821,
        0xf61e2562,0xc040b340,0x265e5a51,0xe9b6c7aa,0xd62f105d,0x02441453,0xd8a1e681,0xe7d3fbc8,
        0x21e1cde6,0xc33707d6,0xf4d50d87,0x455a14ed,0xa9e3e905,0xfcefa3f8,0x676f02d9,0x8d2a4c8a,
        0xfffa3942,0x8771f681,0x6d9d6122,0xfde5380c,0xa4beea44,0x4bdecfa9,0xf6bb4b60,0xbebfbc70,
        0x289b7ec6,0xeaa127fa,0xd4ef3085,0x04881d05,0xd9d4d039,0xe6db99e5,0x1fa27cf8,0xc4ac5665,
        0xf4292244,0x432aff97,0xab9423a7,0xfc93a039,0x655b59c3,0x8f0ccc92,0xffeff47d,0x85845dd1,
        0x6fa87e4f,0xfe2ce6e0,0xa3014314,0x4e0811a1,0xf7537e82,0xbd3af235,0x2ad7d2bb,0xeb86d391};
    const int Sh[64] = {
        7,12,17,22,7,12,17,22,7,12,17,22,7,12,17,22,
        5,9,14,20,5,9,14,20,5,9,14,20,5,9,14,20,
        4,11,16,23,4,11,16,23,4,11,16,23,4,11,16,23,
        6,10,15,21,6,10,15,21,6,10,15,21,6,10,15,21};
    uint32_t A=0x67452301, B=0xefcdab89, C=0x98badcfe, D=0x10325476;
    #pragma unroll
    for (int i = 0; i < 64; i++) {
        uint32_t F; int g;
        if (i < 16)      { F = (B & C) | (~B & D);  g = i; }
        else if (i < 32) { F = (D & B) | (~D & C);  g = (5*i + 1) & 15; }
        else if (i < 48) { F = B ^ C ^ D;           g = (3*i + 5) & 15; }
        else             { F = C ^ (B | ~D);        g = (7*i) & 15; }
        F = F + A + K[i] + M[g];
        A = D; D = C; C = B; B = B + drotl(F, Sh[i]);
    }
    A += 0x67452301; B += 0xefcdab89; C += 0x98badcfe; D += 0x10325476;
    uint32_t h[4] = {A,B,C,D};
    #pragma unroll
    for (int i = 0; i < 4; i++) { out[i*4]=h[i]; out[i*4+1]=h[i]>>8; out[i*4+2]=h[i]>>16; out[i*4+3]=h[i]>>24; }
}

// Convenience: MD5(a||b||c), total <= 55.
MB_MD5_HD inline void d_md5(const uint8_t* a, int la, const uint8_t* b, int lb,
                            const uint8_t* c, int lc, uint8_t out[16])
{
    uint32_t M[16];
    d_md5_buildM(a, la, b, lb, c, lc, M);
    d_md5_compress(M, out);
}

} // namespace mb
