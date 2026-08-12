// gen_vector.cpp — synthetic MultiBit Classic .key test-vector generator.
//
// The exact INVERSE of the crack pipeline: derive keys from (password, salt), build a valid
// wallet-header plaintext, AES-256-CBC *encrypt* the first two blocks, and emit a
// `$multibit$1*<salt>*<data>` line (hashcat m22500 format). Every generated vector is
// self-verified by running it back through the validated cracker (src/pipeline_ref.h).
//
// Build:  g++ -O2 -std=c++17 -I../src gen_vector.cpp -o gen_vector      (from tools/)
//    or:  g++ -O2 -std=c++17 -Isrc tools/gen_vector.cpp -o gen_vector   (from repo root)
//
// Examples:
//   gen_vector --pass hunter2                         > wallet.hash    # MultiBit Classic (base58)
//   gen_vector --pass s3cret --type bitcoinj          > bj.hash
//   gen_vector --pass p@ss   --type knc --salt 0011223344556677
//   gen_vector --selftest                             # round-trip checks, no output file
//   gen_vector --suite ./vectors                      # write a labelled regression suite
#include <cstdio>
#include <cstring>
#include <cstdint>
#include <string>
#include <vector>
#include <stdexcept>
#include "md5_ref.h"
#include "aes_ref.h"
#include "pipeline_ref.h"
#include "mask.h"

using namespace mb;

// ---- helpers ----
static std::string to_hex(const uint8_t* p, size_t n) {
    static const char* h = "0123456789abcdef";
    std::string s; s.reserve(n*2);
    for (size_t i=0;i<n;i++){ s.push_back(h[p[i]>>4]); s.push_back(h[p[i]&15]); }
    return s;
}
static void from_hex(const std::string& s, uint8_t* out, size_t n) {
    if (s.size() != n*2) throw std::runtime_error("hex length mismatch");
    for (size_t i=0;i<n;i++){ int hi=hexval(s[2*i]),lo=hexval(s[2*i+1]); if(hi<0||lo<0) throw std::runtime_error("bad hex"); out[i]=(uint8_t)((hi<<4)|lo); }
}

// EVP_BytesToKey(MD5, count=1): key = D1||D2 (32B), iv = D3 (16B)
static void derive(const uint8_t* pw, size_t pwlen, const uint8_t salt[8],
                   uint8_t key[32], uint8_t iv[16]) {
    uint8_t d1[16], d2[16];
    { MD5 m; m.update(pw,pwlen); m.update(salt,8); m.final(d1); }
    { MD5 m; m.update(d1,16); m.update(pw,pwlen); m.update(salt,8); m.final(d2); }
    { MD5 m; m.update(d2,16); m.update(pw,pwlen); m.update(salt,8); m.final(iv); }
    memcpy(key, d1, 16); memcpy(key+16, d2, 16);
}

// AES-256-CBC encrypt exactly two blocks (the 32 bytes hashcat m22500 stores).
static void cbc_encrypt_2(const uint8_t key[32], const uint8_t iv[16],
                          const uint8_t plain[32], uint8_t data[32]) {
    AES256 aes; aes.expand_key(key);
    uint8_t x[16];
    for (int i=0;i<16;i++) x[i] = plain[i] ^ iv[i];        // P0 ^ IV
    aes.encrypt_block(x, data);                            // C0
    for (int i=0;i<16;i++) x[i] = plain[16+i] ^ data[i];   // P1 ^ C0
    aes.encrypt_block(x, data+16);                         // C1
}

// Build a 32-byte plaintext that passes the m22500 structural check for `kind`.
static void build_plaintext(WalletKind kind, const std::string& custom, uint8_t plain[32]) {
    memset(plain, 0, 32);
    if (!custom.empty()) {
        size_t n = custom.size() > 32 ? 32 : custom.size();
        memcpy(plain, custom.data(), n);
        return;
    }
    switch (kind) {
        case WK_MULTIBIT: {
            // 32 base58 chars, first byte in {K,L,Q,5} (WIF-like)
            const char* s = "L5EZftvrYaSudiozVRzTqLcHLNDoVn7H"; // 31 base58 + pad below
            memcpy(plain, s, 31);
            plain[31] = 'A';                                    // any base58 char
            break;
        }
        case WK_BITCOINJ: {
            // protobuf: field1 tag 0x0a, len 0x16, "org.bitcoin.production"
            const char* s = "\x0a\x16org.bitcoin.production";
            memcpy(plain, s, 24);                               // bytes 24..31 unchecked -> 0
            break;
        }
        case WK_KNC: {
            const char* s = "# KEEP YOUR PRIVATE KEYS SAFE! A"; // exactly 32 bytes
            memcpy(plain, s, 32);
            break;
        }
        default: throw std::runtime_error("unknown wallet kind");
    }
}

static WalletKind parse_kind(const std::string& s) {
    if (s=="multibit"||s=="classic") return WK_MULTIBIT;
    if (s=="bitcoinj") return WK_BITCOINJ;
    if (s=="knc"||s=="kncgroup") return WK_KNC;
    throw std::runtime_error("type must be: multibit | bitcoinj | knc");
}

// Generate one vector. Returns the hash line; fills round-trip verification info.
struct Vector { std::string line; WalletKind kind; std::string pass, plaintext_hex; };

static Vector generate(const std::string& pass, WalletKind kind,
                       const uint8_t* salt_opt /*8 bytes or null*/, const std::string& custom) {
    uint8_t salt[8];
    if (salt_opt) memcpy(salt, salt_opt, 8);
    else { uint8_t d[16]; md5(pass.data(), pass.size(), d); memcpy(salt, d, 8); } // deterministic default

    uint8_t key[32], iv[16];
    derive((const uint8_t*)pass.data(), pass.size(), salt, key, iv);

    uint8_t plain[32]; build_plaintext(kind, custom, plain);
    uint8_t data[32];  cbc_encrypt_2(key, iv, plain, data);

    Vector v;
    v.line = "$multibit$1*" + to_hex(salt,8) + "*" + to_hex(data,32);
    v.kind = kind; v.pass = pass; v.plaintext_hex = to_hex(plain,32);

    // ---- self-verify: the validated cracker must recover the right kind ----
    Target t = parse_hash(v.line);
    WalletKind got = try_password(t, (const uint8_t*)pass.data(), pass.size());
    if (got != kind)
        throw std::runtime_error("SELF-VERIFY FAILED: generated vector does not round-trip (got " +
                                 std::string(wallet_name(got)) + ", expected " + wallet_name(kind) + ")");
    // a wrong password must NOT verify (guards against a degenerate all-accept vector)
    if (try_password(t, (const uint8_t*)"\x01wrong", 6) != WK_NONE)
        throw std::runtime_error("SELF-VERIFY FAILED: a wrong password also verified");
    return v;
}

int main(int argc, char** argv) {
    try {
        std::string pass, type = "multibit", salt_hex, custom, suite_dir;
        bool selftest = false, do_suite = false;
        for (int i=1;i<argc;i++){
            std::string a = argv[i];
            auto need=[&](const char* w)->std::string{ if(i+1>=argc) throw std::runtime_error(std::string("missing value for ")+w); return argv[++i]; };
            if (a=="--pass") pass=need("--pass");
            else if (a=="--type") type=need("--type");
            else if (a=="--salt") salt_hex=need("--salt");
            else if (a=="--plaintext") custom=need("--plaintext");
            else if (a=="--selftest") selftest=true;
            else if (a=="--suite"){ do_suite=true; suite_dir=need("--suite"); }
            else throw std::runtime_error("unknown arg: "+a);
        }

        if (selftest) {
            // 1) FIPS-197 encrypt KAT (proves the new encrypt path)
            {
                uint8_t key[32]; for(int i=0;i<32;i++)key[i]=(uint8_t)i;
                uint8_t pt[16]={0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff};
                uint8_t exp[16]={0x8e,0xa2,0xb7,0xca,0x51,0x67,0x45,0xbf,0xea,0xfc,0x49,0x90,0x4b,0x49,0x60,0x89};
                AES256 a; a.expand_key(key); uint8_t ct[16]; a.encrypt_block(pt,ct);
                printf("%s FIPS-197 AES-256 encrypt KAT\n", memcmp(ct,exp,16)?"[FAIL]":"[ ok ]");
            }
            // 2) encrypt is the exact inverse of decrypt on the REAL self-test vector
            {
                const std::string ST="$multibit$1*e5912fe5c84af3d5*"
                  "5f0391c219e8ef62c06505b1f6232858f5bcaa739c2b471d45dd0bd8345334de";
                Target t=parse_hash(ST);
                uint8_t key[32],iv[16]; derive((const uint8_t*)"hashcat",7,t.salt,key,iv);
                AES256 a; a.expand_key(key);
                uint8_t p0[16],p1[16];
                a.decrypt_block(t.data,p0);   for(int i=0;i<16;i++)p0[i]^=iv[i];
                a.decrypt_block(t.data+16,p1);for(int i=0;i<16;i++)p1[i]^=t.data[i];
                uint8_t plain[32]; memcpy(plain,p0,16); memcpy(plain+16,p1,16);
                uint8_t re[32]; cbc_encrypt_2(key,iv,plain,re);
                printf("%s encrypt(decrypt(ST_HASH)) == ST_HASH data  [plaintext=\"%.32s\"]\n",
                       memcmp(re,t.data,32)?"[FAIL]":"[ ok ]", (const char*)plain);
            }
            // 3) generate each type and crack it back with a tiny mask
            const char* pw="Zx7";
            for (WalletKind k : {WK_MULTIBIT, WK_BITCOINJ, WK_KNC}) {
                Vector v = generate(pw, k, nullptr, "");
                Mask m; m.parse("Zx?a");  // fastest position covers the last char (incl '7')
                Target t=parse_hash(v.line);
                uint64_t N=m.keyspace(); bool found=false; uint8_t buf[32];
                for(uint64_t i=0;i<N;i++){ m.index_to_password(i,buf); if(try_password(t,buf,m.length())==k){found=true;break;} }
                printf("%s generate+crack %-9s pass=\"%s\"\n", found?"[ ok ]":"[FAIL]", wallet_name(k), pw);
            }
            printf("\nself-test complete\n");
            return 0;
        }

        if (do_suite) {
            struct Case { const char* pass; const char* type; };
            const Case cases[] = {
                {"hunter2","multibit"}, {"correct horse","multibit"},
                {"s3cret!","bitcoinj"}, {"p@ssw0rd","knc"}, {"Zx7","multibit"},
            };
            std::string index;
            for (const auto& c : cases) {
                Vector v = generate(c.pass, parse_kind(c.type), nullptr, "");
                std::string fn = suite_dir + "/" + c.type + "_" + std::string(c.pass).substr(0, 8);
                for (auto& ch : fn) if (ch==' '||ch=='!'||ch=='@') ch='_';
                fn += ".hash";
                FILE* f = fopen(fn.c_str(), "w");
                if (!f) throw std::runtime_error("cannot write "+fn);
                fprintf(f, "%s\n", v.line.c_str()); fclose(f);
                fprintf(stderr, "wrote %-40s pass=\"%s\" type=%s\n", fn.c_str(), c.pass, c.type);
                index += fn + "\t" + c.pass + "\t" + c.type + "\n";
            }
            std::string idxfn = suite_dir + "/INDEX.tsv";
            FILE* f = fopen(idxfn.c_str(), "w"); if (f){ fputs(index.c_str(), f); fclose(f); }
            fprintf(stderr, "suite written to %s (see INDEX.tsv: file<TAB>password<TAB>type)\n", suite_dir.c_str());
            return 0;
        }

        if (pass.empty()) { fprintf(stderr,
            "usage: gen_vector --pass <pw> [--type multibit|bitcoinj|knc] [--salt <16hex>] [--plaintext <s>]\n"
            "       gen_vector --selftest\n"
            "       gen_vector --suite <dir>\n"); return 2; }
        if (pass.size() > 31) fprintf(stderr,
            "warning: password length %zu > 31; the OPTIMIZED cracker only handles <=31 (still valid data)\n", pass.size());

        uint8_t salt[8]; const uint8_t* saltp = nullptr;
        if (!salt_hex.empty()) { from_hex(salt_hex, salt, 8); saltp = salt; }

        Vector v = generate(pass, parse_kind(type), saltp, custom);
        printf("%s\n", v.line.c_str());                       // stdout: clean hash line
        fprintf(stderr, "# type=%s  pass=\"%s\"  plaintext=%s  [self-verify: OK]\n",
                type.c_str(), pass.c_str(), v.plaintext_hex.c_str());
        return 0;
    } catch (const std::exception& e) {
        fprintf(stderr, "error: %s\n", e.what());
        return 1;
    }
}
