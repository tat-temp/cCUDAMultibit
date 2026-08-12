// selftest.cpp — validates the CPU reference pipeline end-to-end.
// Build (no CUDA needed):   g++ -O2 -std=c++17 -I../src selftest.cpp -o selftest
// Expected: recovers password "hashcat" from the module's ST_HASH vector.
#include <cstdio>
#include <cstring>
#include <string>
#include "pipeline_ref.h"
#include "mask.h"

using namespace mb;

int main() {
    int failures = 0;

    // ---- 1. Known-answer test for MD5 (sanity) ----
    {
        uint8_t d[16];
        md5("abc", 3, d);
        const uint8_t exp[16] = {0x90,0x01,0x50,0x98,0x3c,0xd2,0x4f,0xb0,
                                 0xd6,0x96,0x3f,0x7d,0x28,0xe1,0x7f,0x72};
        if (memcmp(d, exp, 16) != 0) { printf("[FAIL] MD5(\"abc\")\n"); failures++; }
        else printf("[ ok ] MD5 KAT\n");
    }

    // ---- 2. AES-256 FIPS-197 known-answer decrypt ----
    {
        // FIPS-197 C.3: key 000102...1f, plaintext 00112233...ff, ciphertext 8ea2b7ca...0b60
        uint8_t key[32]; for (int i=0;i<32;i++) key[i]=(uint8_t)i;
        uint8_t ct[16] = {0x8e,0xa2,0xb7,0xca,0x51,0x67,0x45,0xbf,
                          0xea,0xfc,0x49,0x90,0x4b,0x49,0x60,0x89};
        uint8_t exp_pt[16] = {0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
                              0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff};
        AES256 aes; aes.expand_key(key);
        uint8_t pt[16]; aes.decrypt_block(ct, pt);
        if (memcmp(pt, exp_pt, 16) != 0) { printf("[FAIL] AES-256 FIPS-197 decrypt\n"); failures++; }
        else printf("[ ok ] AES-256 FIPS-197 KAT\n");
    }

    // ---- 3. m22500 pipeline: direct password test ----
    const std::string ST_HASH =
        "$multibit$1*e5912fe5c84af3d5*"
        "5f0391c219e8ef62c06505b1f6232858f5bcaa739c2b471d45dd0bd8345334de";
    Target t = parse_hash(ST_HASH);
    {
        const char* pw = "hashcat";
        WalletKind k = try_password(t, (const uint8_t*)pw, strlen(pw));
        if (k == WK_NONE) { printf("[FAIL] direct: 'hashcat' rejected\n"); failures++; }
        else printf("[ ok ] direct: 'hashcat' accepted -> %s\n", wallet_name(k));
    }
    {
        const char* pw = "wrongpw";
        WalletKind k = try_password(t, (const uint8_t*)pw, strlen(pw));
        if (k != WK_NONE) { printf("[FAIL] direct: 'wrongpw' falsely accepted\n"); failures++; }
        else printf("[ ok ] direct: 'wrongpw' correctly rejected\n");
    }

    // ---- 4. m22500 through the mask engine (brute a 7-char lowercase space slice) ----
    // Full ?l^7 is ~8e9 (too slow for a smoke test), so brute only the last char and
    // pin the first 6 to "hashca" to prove index<->password + crack loop wiring.
    {
        Mask m;
        m.parse("hashca?l");          // positions: h a s h c a [a-z]
        uint64_t N = m.keyspace();    // = 26
        uint8_t pw[8];
        uint64_t found = UINT64_MAX;
        WalletKind fk = WK_NONE;
        for (uint64_t i = 0; i < N; i++) {
            m.index_to_password(i, pw);
            WalletKind k = try_password(t, pw, m.length());
            if (k != WK_NONE) { found = i; fk = k; break; }
        }
        if (found == UINT64_MAX) { printf("[FAIL] mask crack: no hit in ?l slice\n"); failures++; }
        else {
            m.index_to_password(found, pw);
            printf("[ ok ] mask crack: idx=%llu pw=\"%.*s\" (%s)\n",
                   (unsigned long long)found, m.length(), (const char*)pw, wallet_name(fk));
            if (memcmp(pw, "hashcat", 7) != 0) { printf("[FAIL] recovered pw != hashcat\n"); failures++; }
        }
    }

    printf(failures ? "\nRESULT: %d FAILURE(S)\n" : "\nRESULT: ALL PASS\n", failures);
    return failures ? 1 : 0;
}
