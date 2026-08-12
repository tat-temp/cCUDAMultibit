// pipeline_ref.h — the exact m22500 per-candidate pipeline, on CPU (g++).
// This is the executable specification the CUDA kernel must reproduce bit-for-bit.
#pragma once
#include <cstdint>
#include <cstring>
#include <string>
#include <stdexcept>
#include "md5_ref.h"
#include "aes_ref.h"
#include "verify.h"

namespace mb {

struct Target {
    uint8_t salt[8];
    uint8_t data[32];   // C0 = data[0..15], C1 = data[16..31]
};

// hex "aa" -> byte. returns -1 on bad nibble
inline int hexval(char c) {
    if (c>='0'&&c<='9') return c-'0';
    if (c>='a'&&c<='f') return c-'a'+10;
    if (c>='A'&&c<='F') return c-'A'+10;
    return -1;
}
inline bool hexdecode(const char* s, uint8_t* out, size_t nbytes) {
    for (size_t i=0;i<nbytes;i++){ int hi=hexval(s[2*i]),lo=hexval(s[2*i+1]); if(hi<0||lo<0) return false; out[i]=(uint8_t)((hi<<4)|lo); }
    return true;
}

// Parse "$multibit$1*<8B hex>*<32B hex>". Bytes are stored in file order (see plan §1.1).
inline Target parse_hash(const std::string& line) {
    const std::string sig = "$multibit$1*";
    if (line.compare(0, sig.size(), sig) != 0) throw std::runtime_error("bad signature / version");
    size_t p = sig.size();
    size_t star = line.find('*', p);
    if (star == std::string::npos) throw std::runtime_error("missing 2nd '*'");
    std::string salt_hex = line.substr(p, star - p);
    std::string data_hex = line.substr(star + 1);
    // trim trailing whitespace/newline on data
    while (!data_hex.empty() && (data_hex.back()=='\n'||data_hex.back()=='\r'||data_hex.back()==' ')) data_hex.pop_back();
    if (salt_hex.size() != 16) throw std::runtime_error("salt must be 16 hex chars");
    if (data_hex.size() != 64) throw std::runtime_error("data must be 64 hex chars");
    Target t;
    if (!hexdecode(salt_hex.c_str(), t.salt, 8)) throw std::runtime_error("bad salt hex");
    if (!hexdecode(data_hex.c_str(), t.data, 32)) throw std::runtime_error("bad data hex");
    return t;
}

// Try one password. Returns wallet kind (WK_NONE if reject). pw need not be NUL-terminated.
inline WalletKind try_password(const Target& t, const uint8_t* pw, size_t pw_len) {
    // OpenSSL EVP_BytesToKey(MD5, count=1): key = D1||D2, iv = D3
    uint8_t d1[16], d2[16], iv[16];
    {
        MD5 m; m.update(pw, pw_len); m.update(t.salt, 8); m.final(d1);
    }
    {
        MD5 m; m.update(d1, 16); m.update(pw, pw_len); m.update(t.salt, 8); m.final(d2);
    }
    {
        MD5 m; m.update(d2, 16); m.update(pw, pw_len); m.update(t.salt, 8); m.final(iv);
    }
    uint8_t aeskey[32];
    memcpy(aeskey, d1, 16); memcpy(aeskey + 16, d2, 16);

    AES256 aes; aes.expand_key(aeskey);

    uint8_t p0[16];
    aes.decrypt_block(t.data, p0);         // decrypt C0
    for (int i=0;i<16;i++) p0[i] ^= iv[i]; // CBC: XOR IV

    if (!first_byte_ok(p0[0])) return WK_NONE;

    uint8_t b = p0[0];
    if (b==0x4b || b==0x4c || b==0x51 || b==0x35) {           // K L Q 5 -> MultiBit Classic
        if (!is_valid_base58_16(p0)) return WK_NONE;
        uint8_t p1[16];
        aes.decrypt_block(t.data + 16, p1);                   // decrypt C1
        for (int i=0;i<16;i++) p1[i] ^= t.data[i];            // XOR prev ciphertext (C0)
        if (!is_valid_base58_16(p1)) return WK_NONE;
        return WK_MULTIBIT;
    } else if (b==0x0a) {                                     // '\n' -> bitcoinj
        if (p0[1] > 0x7f) return WK_NONE;
        if (p0[2]!='o'||p0[3]!='r'||p0[4]!='g'||p0[5]!='.') return WK_NONE; // "org." at offset 2
        for (int i=6;i<=13;i++) if (!is_valid_bitcoinj_8(p0[i])) return WK_NONE;
        return WK_BITCOINJ;
    } else {                                                 // '#' -> KnCGroup
        if (memcmp(p0, "# KEEP YOUR PRIV", 16) != 0) return WK_NONE;
        uint8_t p1[16];
        aes.decrypt_block(t.data + 16, p1);
        for (int i=0;i<16;i++) p1[i] ^= t.data[i];
        if (memcmp(p1, "ATE KEYS SAFE! A", 16) != 0) return WK_NONE;
        return WK_KNC;
    }
}

inline const char* wallet_name(WalletKind k) {
    switch (k) { case WK_MULTIBIT: return "MultiBit Classic";
                 case WK_BITCOINJ: return "bitcoinj";
                 case WK_KNC:      return "KnCGroup";
                 default:          return "none"; }
}

} // namespace mb
