// selftest.cpp — validates the CPU reference pipeline end-to-end.
// Build (no CUDA needed):   g++ -O2 -std=c++17 -I../src selftest.cpp -o selftest
// Expected: recovers password "hashcat" from the module's ST_HASH vector.
#include <cstdio>
#include <cstring>
#include <string>
#include "pipeline_ref.h"
#include "mask.h"
#include "aes.cuh"      // T-table AES (aes256_expand_dec / aes256_decrypt_tt) — host-callable via MB_AES_HD
#include "md5.cuh"      // device MD5 (d_md5 / d_md5_buildM) — host-callable via MB_MD5_HD
#include "cuda_stub.h"  // map __device__/etc. to no-ops so the real device pipeline runs on host
#include "pipeline.cuh" // device per-candidate pipeline (dev_try_password) — validated vs reference

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

    // ---- 5. T-table AES-256 (in-place key schedule) == byte-oriented reference, many vectors ----
    {
        AesTd tb; aes_build_tables(tb);
        uint32_t seed = 0xC0FFEEu;
        auto rnd = [&]() { seed = seed * 1664525u + 1013904223u; return seed; };
        int mism = 0;
        for (int trial = 0; trial < 50000; trial++) {
            uint8_t key[32], ct[16];
            for (int i = 0; i < 32; i++) key[i] = (uint8_t)(rnd() >> 24);
            for (int i = 0; i < 16; i++) ct[i]  = (uint8_t)(rnd() >> 24);
            uint32_t dk[60];
            aes256_expand_dec(key, dk, tb.sbox, tb.IMC0, tb.IMC1, tb.IMC2, tb.IMC3);
            uint8_t got[16];
            aes256_decrypt_tt(dk, ct, got, tb.Td0, tb.Td1, tb.Td2, tb.Td3, tb.isbox);
            AES256 ref; ref.expand_key(key);
            uint8_t exp[16]; ref.decrypt_block(ct, exp);
            if (memcmp(got, exp, 16) != 0) mism++;
            // Step 3 fast path: 13 middle rounds + byte0 must equal the full decrypt's byte 0.
            uint32_t st0, st1, st2, st3;
            aes256_decrypt_rounds(dk, ct, st0, st1, st2, st3, tb.Td0, tb.Td1, tb.Td2, tb.Td3);
            if (aes256_decrypt_byte0(dk, st0, tb.isbox) != got[0]) mism++;
        }
        if (mism) { printf("[FAIL] T-table AES decrypt != reference (%d/50000)\n", mism); failures++; }
        else printf("[ ok ] T-table AES-256 decrypt == reference (50000 random vectors)\n");
    }

    // ---- 5b. P1 invariant: the precomputed IMC tables equal the fused Tdk[sbox[b]] they replace ----
    // The schedule InvMixColumns pass now reads IMCk[b] directly; this asserts IMCk[b] == Tdk[sbox[b]]
    // for all 256 b, so a table-gen typo can't silently change any decrypt (defence-in-depth on top of
    // the 50000-vector end-to-end check above, which already routes through the IMC path).
    {
        AesTd tb; aes_build_tables(tb);
        int mism = 0;
        for (int b = 0; b < 256; b++) {
            uint8_t s = tb.sbox[b];
            if (tb.IMC0[b] != tb.Td0[s] || tb.IMC1[b] != tb.Td1[s] ||
                tb.IMC2[b] != tb.Td2[s] || tb.IMC3[b] != tb.Td3[s]) mism++;
        }
        if (mism) { printf("[FAIL] IMCk[b] != Tdk[sbox[b]] (%d/256)\n", mism); failures++; }
        else printf("[ ok ] P1 IMC tables == Tdk[sbox[b]] (256/256)\n");
    }

    // ---- 5c. Bank-pinned Td0 decrypt == standard 4-table decrypt (every lane column) ----
    // A 32-wide column-major Td0 replica (entry v at [v*32+lane]) + register rotates (Td_j=ror(Td0,8j))
    // must reproduce the 4-table decrypt for EVERY lane 0..31. This is the correctness proof behind the
    // conflict-free MB_BANK_PIN kernel path; the device gets R=1.0 from the layout, the values are these.
    {
        AesTd tb; aes_build_tables(tb);
        static uint32_t Td0p[256*32];
        for (int v = 0; v < 256; v++) for (int j = 0; j < 32; j++) Td0p[v*32 + j] = tb.Td0[v];
        uint32_t seed = 0x9E3779B9u;
        auto rnd = [&](){ seed = seed*1664525u + 1013904223u; return seed; };
        int mism = 0;
        for (int trial = 0; trial < 20000; trial++) {
            uint8_t key[32], ct[16];
            for (int i = 0; i < 32; i++) key[i] = (uint8_t)(rnd() >> 24);
            for (int i = 0; i < 16; i++) ct[i]  = (uint8_t)(rnd() >> 24);
            uint32_t dk[60];
            aes256_expand_dec(key, dk, tb.sbox, tb.IMC0, tb.IMC1, tb.IMC2, tb.IMC3);
            uint32_t r0,r1,r2,r3; aes256_decrypt_rounds(dk, ct, r0,r1,r2,r3, tb.Td0,tb.Td1,tb.Td2,tb.Td3);
            uint32_t lane = rnd() & 31u;
            uint32_t p0,p1,p2,p3; aes256_decrypt_rounds_pin(dk, ct, p0,p1,p2,p3, Td0p, lane);
            if (p0!=r0 || p1!=r1 || p2!=r2 || p3!=r3) mism++;
            uint8_t g0[16], g1[16];
            aes256_decrypt_tt(dk, ct, g0, tb.Td0,tb.Td1,tb.Td2,tb.Td3, tb.isbox);
            aes256_decrypt_tt_pin(dk, ct, g1, Td0p, lane, tb.isbox);
            if (memcmp(g0,g1,16) != 0) mism++;
        }
        // sweep all 32 columns on one fixed vector (every lane must give the identical plaintext)
        uint8_t key[32], ct[16];
        for (int i = 0; i < 32; i++) key[i] = (uint8_t)(3*i+1);
        for (int i = 0; i < 16; i++) ct[i]  = (uint8_t)(5*i+2);
        uint32_t dk[60]; aes256_expand_dec(key, dk, tb.sbox, tb.IMC0,tb.IMC1,tb.IMC2,tb.IMC3);
        uint8_t ref[16]; aes256_decrypt_tt(dk, ct, ref, tb.Td0,tb.Td1,tb.Td2,tb.Td3, tb.isbox);
        for (uint32_t lane = 0; lane < 32; lane++) {
            uint8_t got[16]; aes256_decrypt_tt_pin(dk, ct, got, Td0p, lane, tb.isbox);
            if (memcmp(ref, got, 16) != 0) mism++;
        }
        if (mism) { printf("[FAIL] bank-pinned Td0 decrypt != reference (%d)\n", mism); failures++; }
        else printf("[ ok ] bank-pinned Td0 (conflict-free decrypt) == reference (20000 vectors + 32-col sweep)\n");
    }

    // ---- 6. Word-oriented MD5 message assembly == reference MD5, every length & shape ----
    // Step 2 removed the uint8_t msg[64] byte buffer; d_md5(a,la,b,lb,c,lc) must still equal
    // md5(a||b||c) for EVERY length the KDF can produce. The risk is the salt tail's placement
    // relative to the variable pw_len (word-boundary math), so sweep all lengths + both KDF shapes.
    {
        uint32_t seed = 0x01234567u;
        auto rnd  = [&]() { seed = seed*1664525u + 1013904223u; return seed; };
        auto fill = [&](uint8_t* p, int n) { for (int i = 0; i < n; i++) p[i] = (uint8_t)(rnd() >> 24); };
        int mism = 0, ntest = 0;
        uint8_t a[64], b[64], c[64], cat[64], got[16], exp[16];

        auto check = [&](int la, int lb, int lc) {
            fill(a, la); fill(b, lb); fill(c, lc);
            int p = 0;
            for (int i = 0; i < la; i++) cat[p++] = a[i];
            for (int i = 0; i < lb; i++) cat[p++] = b[i];
            for (int i = 0; i < lc; i++) cat[p++] = c[i];
            md5(cat, p, exp);                       // reference: MD5 of the concatenation
            d_md5(a, la, b, lb, c, lc, got);        // device word-oriented assembly + compress
            ntest++;
            if (memcmp(got, exp, 16) != 0) mism++;
        };

        for (int L = 1; L <= 47; L++) check(L, 8, 0);   // Shape A (key1): pw(L)||salt(8), total<=55
        for (int L = 1; L <= 31; L++) check(16, L, 8);  // Shape B (key2/iv): dgst(16)||pw(L)||salt(8)
        for (int t = 0; t <= 55; t++) check(t, 0, 0);   // single field, every length incl. 0 and 55
        for (int la = 0; la <= 20; la++)                // vary salt-tail alignment against a prefix
            for (int lc = 0; lc <= 8; lc++)
                if (la + 8 + lc <= 55) check(la, 8, lc);
        for (int t = 0; t < 4000; t++) {                // random triples across the legal range
            int la = rnd() % 16, lb = rnd() % 16, lc = rnd() % 8;   // worst case 15+15+7=37 <= 55
            check(la, lb, lc);
        }

        if (mism) { printf("[FAIL] word MD5 assembly != reference (%d/%d vectors)\n", mism, ntest); failures++; }
        else printf("[ ok ] word MD5 assembly == reference (%d vectors: shapes A/B + edges + random)\n", ntest);
    }

    // ---- 7. Device per-candidate pipeline (dev_try_password) == CPU reference (try_password) ----
    // Runs the EXACT device glue on host (via cuda_stub.h): MD5 KDF, AES expand + first-block
    // decrypt, the Step-3 first-byte fast-path reject, and the wallet-structure predicates. The
    // one accept ('hashcat') exercises the full/survivor path; the rest exercise the fast reject.
    {
        AesTd tbl; aes_build_tables(tbl);
        AesShared sh; sh.Td0=tbl.Td0; sh.Td1=tbl.Td1; sh.Td2=tbl.Td2; sh.Td3=tbl.Td3;
        sh.IMC0=tbl.IMC0; sh.IMC1=tbl.IMC1; sh.IMC2=tbl.IMC2; sh.IMC3=tbl.IMC3;
        sh.sbox=tbl.sbox; sh.isbox=tbl.isbox;
        int mism = 0, ntest = 0;
        auto cmp = [&](const uint8_t* pw, int L) {
            int        dev = dev_try_password(t.salt, t.data, pw, L, sh);
            WalletKind ref = try_password(t, pw, L);
            ntest++;
            if (dev != (int)ref) { mism++; printf("   mismatch: pw len=%d dev=%d ref=%d\n", L, dev, (int)ref); }
        };
        const char* words[] = {"hashcat","wrongpw","a","hashca","hashcat1","password","","zzzzzzzz","HASHCAT","hashcaT"};
        for (const char* w : words) cmp((const uint8_t*)w, (int)strlen(w));
        // brute a mask slice so many candidates flow through the fast reject path
        {
            Mask m; m.parse("hashca?l"); uint8_t pwb[8];
            for (uint64_t i = 0; i < m.keyspace(); i++) {
                m.index_to_password(i, pwb);
                cmp(pwb, m.length());
            }
        }
        if (mism) { printf("[FAIL] device pipeline != reference (%d/%d)\n", mism, ntest); failures++; }
        else printf("[ ok ] device pipeline == reference (%d passwords: accept + fast-path rejects)\n", ntest);
    }

    printf(failures ? "\nRESULT: %d FAILURE(S)\n" : "\nRESULT: ALL PASS\n", failures);
    return failures ? 1 : 0;
}
