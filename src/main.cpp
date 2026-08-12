// main.cpp — mbcrack CLI. MultiBit m22500 custom-charset brute-forcer.
//
// CPU build (works today, no CUDA):
//     g++ -O3 -std=c++17 -pthread src/main.cpp -o mbcrack
// GPU build (Phase 4+, needs CUDA >= 12.8 + sm_120):
//     nvcc -O3 -std=c++17 -DUSE_CUDA -arch=sm_120 src/main.cpp src/kernel.cu -o mbcrack
//
// Usage:
//     mbcrack <hash|hashfile> -a 3 <mask> [options]
//   options:
//     -1 <chars> .. -4 <chars>   define custom charsets ?1..?4
//     --skip N                    start index
//     --limit N                   number of candidates to try
//     -j N                        CPU threads (CPU backend only; default hw concurrency)
//     -d N                        CUDA device id (GPU backend)
//   examples:
//     mbcrack '$multibit$1*e591...34de' -a 3 'hashca?l'
//     mbcrack wallet.hash -a 3 '?1?1?1?1?1?1?1' -1 abcdefghijklmnopqrstuvwxyz
#include <cstdio>
#include <cstring>
#include <cstdint>
#include <string>
#include <thread>
#include <atomic>
#include <vector>
#include <chrono>
#include <algorithm>
#include "pipeline_ref.h"
#include "mask.h"
#ifdef USE_CUDA
#include "cuda_backend.h"
#endif

using namespace mb;

static std::string load_hash(const std::string& arg) {
    // If it looks like a hash line, use it directly; else treat as a file path.
    // Uses C stdio (not std::ifstream) for portability — avoids a locale-init crash seen
    // with some MinGW/MSYS2 libstdc++ builds, and is fine everywhere else.
    if (arg.rfind("$multibit$", 0) == 0) return arg;
    FILE* f = fopen(arg.c_str(), "r");
    if (!f) throw std::runtime_error("cannot open hash file: " + arg);
    char buf[4096];
    char* got = fgets(buf, sizeof(buf), f);
    fclose(f);
    if (!got) throw std::runtime_error("hash file is empty: " + arg);
    std::string line(buf);
    while (!line.empty() && (line.back()=='\r'||line.back()=='\n'||line.back()==' ')) line.pop_back();
    return line;
}

// ---- CPU backend: multithreaded brute of [skip, skip+count) ----
struct CpuResult { std::atomic<bool> found{false}; std::atomic<uint64_t> index{0}; int kind{0}; };

static void cpu_worker(const Target* t, const Mask* m, uint64_t begin, uint64_t end,
                       CpuResult* res, std::atomic<uint64_t>* progress) {
    uint8_t pw[32];
    int len = m->length();
    for (uint64_t i = begin; i < end; i++) {
        if ((i & 0xffff) == 0) {
            if (res->found.load(std::memory_order_relaxed)) return;
            progress->fetch_add(0x10000, std::memory_order_relaxed);
        }
        m->index_to_password(i, pw);
        WalletKind k = try_password(*t, pw, len);
        if (k != WK_NONE) {
            bool expected = false;
            if (res->found.compare_exchange_strong(expected, true)) {
                res->index.store(i); res->kind = k;
            }
            return;
        }
    }
}

int main(int argc, char** argv) {
    try {
        if (argc < 4) { fprintf(stderr, "usage: mbcrack <hash|file> -a 3 <mask> [opts]\n"); return 2; }

        std::string hash_arg = argv[1];
        std::string mask_str;
        Mask mask;
        uint64_t skip = 0, limit = 0; // limit 0 => whole keyspace
        int threads = (int)std::thread::hardware_concurrency(); if (threads <= 0) threads = 4;
        int device_id = 0;

        for (int i = 2; i < argc; i++) {
            std::string a = argv[i];
            auto need = [&](const char* what) -> std::string {
                if (i + 1 >= argc) throw std::runtime_error(std::string("missing value for ") + what);
                return argv[++i];
            };
            if (a == "-a")            { std::string mode = need("-a"); if (mode != "3") throw std::runtime_error("only -a 3 (mask) implemented"); }
            else if (a == "--skip")   skip = strtoull(need("--skip").c_str(), nullptr, 10);
            else if (a == "--limit")  limit = strtoull(need("--limit").c_str(), nullptr, 10);
            else if (a == "-j")       threads = atoi(need("-j").c_str());
            else if (a == "-d")       device_id = atoi(need("-d").c_str());
            else if (a.size()==2 && a[0]=='-' && a[1]>='1' && a[1]<='4') mask.add_custom(a[1], need(a.c_str()));
            else if (!a.empty() && a[0] != '-') mask_str = a;
            else throw std::runtime_error("unknown arg: " + a);
        }
        if (mask_str.empty()) throw std::runtime_error("no mask given");

        Target t = parse_hash(load_hash(hash_arg));
        mask.parse(mask_str);
        uint64_t N = mask.keyspace();
        uint64_t begin = skip;
        uint64_t end = (limit == 0) ? N : std::min<uint64_t>(N, skip + limit);
        if (begin >= end) { fprintf(stderr, "empty range\n"); return 2; }

        printf("target parsed. mask length=%d  keyspace=%llu  range=[%llu,%llu)\n",
               mask.length(), (unsigned long long)N, (unsigned long long)begin, (unsigned long long)end);

        auto t0 = std::chrono::steady_clock::now();

#ifdef USE_CUDA
        printf("backend: CUDA (device %d)\n", device_id);
        CrackResult r = cuda_crack(t, mask, begin, end - begin, device_id);
        bool found = r.found; uint64_t hit = r.index; int kind = r.kind;
#else
        printf("backend: CPU (%d threads)\n", threads);
        CpuResult res; std::atomic<uint64_t> progress{0};
        std::vector<std::thread> pool;
        uint64_t span = end - begin, chunk = (span + threads - 1) / threads;
        for (int ti = 0; ti < threads; ti++) {
            uint64_t b = begin + (uint64_t)ti * chunk;
            uint64_t e = std::min(end, b + chunk);
            if (b < e) pool.emplace_back(cpu_worker, &t, &mask, b, e, &res, &progress);
        }
        for (auto& th : pool) th.join();
        bool found = res.found; uint64_t hit = res.index; int kind = res.kind;
#endif
        auto t1 = std::chrono::steady_clock::now();
        double secs = std::chrono::duration<double>(t1 - t0).count();
        double rate = (double)(end - begin) / (secs > 0 ? secs : 1);

        if (found) {
            uint8_t pw[32]; mask.index_to_password(hit, pw);
            printf("\nCRACKED: index=%llu  password=\"%.*s\"  wallet=%s\n",
                   (unsigned long long)hit, mask.length(), (const char*)pw, wallet_name((WalletKind)kind));
        } else {
            printf("\nexhausted range, no match.\n");
        }
        printf("elapsed=%.2fs  ~%.2f Mcand/s\n", secs, rate / 1e6);
        return found ? 0 : 1;
    } catch (const std::exception& e) {
        fprintf(stderr, "error: %s\n", e.what());
        return 2;
    }
}
