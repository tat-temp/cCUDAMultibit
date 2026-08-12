// kernel.cu — Phase-6 CUDA backend for mbcrack (RTX 5090 / sm_120).
//
// Optimizations vs the Phase-4 skeleton:
//   1. AES-256 T-tables (Td0..Td3 + S-boxes) staged into SHARED memory once per block.
//   2. a3 amplifier: one thread per BASE word (mask positions 1..L-1); an inner loop walks
//      the fastest-varying position 0. Charset decode, key1 MD5 message assembly, and table
//      staging are all amortized across the inner charset (hashcat's w0l|w0r trick).
//   3. key1 = MD5(pw||salt) message is built once per base; only M[0]'s low byte changes.
//   4. __launch_bounds__ to bound registers; single __syncthreads (table staging only).
//
// Every candidate goes through the SAME math as src/pipeline_ref.h (the g++-validated CPU
// reference) -- verified bit-identical in the Phase-6 stub tests.
//
// Build: nvcc -O3 -use_fast_math -DUSE_CUDA -arch=sm_120 -Isrc src/main.cpp src/kernel.cu -o mbcrack
#include <cuda_runtime.h>
#include <algorithm>
#include <cstdio>
#include <cstring>
#include <vector>
#include "pipeline.cuh"      // dev_finish_from_key1, AesShared, md5/aes/verify
#include "cuda_backend.h"    // host Target/Mask/CrackResult

namespace mb {

#define MB_MAX_LEN 32
#define MB_MAX_CS  1024
#define MB_THREADS 256                  // tune with `make gate` / Nsight Compute

// ---- constant memory: target + mask ----
__constant__ uint8_t  c_salt[8];
__constant__ uint8_t  c_data[32];
__constant__ uint8_t  c_cs_data[MB_MAX_CS];
__constant__ uint32_t c_cs_off[MB_MAX_LEN];
__constant__ uint32_t c_cs_len[MB_MAX_LEN];
__constant__ int      c_pw_len;
__constant__ uint32_t c_n0;             // size of position-0 charset (inner loop)
__constant__ uint32_t c_cs0_off;        // offset of position-0 charset in c_cs_data

// ---- AES tables in global memory (staged to shared each block) ----
__device__ uint32_t g_Td0[256], g_Td1[256], g_Td2[256], g_Td3[256];
__device__ uint8_t  g_sbox[256], g_isbox[256];

struct DevResult { int found; unsigned long long index; uint8_t pw[32]; int kind; };
__device__ DevResult d_res;

// base index in [base_begin, base_begin+base_count); each base fans out over c_n0 candidates.
__launch_bounds__(MB_THREADS, 2)
__global__ void crack_kernel(uint64_t base_begin, uint64_t base_count)
{
    __shared__ uint32_t sTd0[256], sTd1[256], sTd2[256], sTd3[256];
    __shared__ uint8_t  sS[256], sIS[256];
    for (int i = threadIdx.x; i < 256; i += blockDim.x) {
        sTd0[i]=g_Td0[i]; sTd1[i]=g_Td1[i]; sTd2[i]=g_Td2[i]; sTd3[i]=g_Td3[i];
        sS[i]=g_sbox[i];  sIS[i]=g_isbox[i];
    }
    __syncthreads();

    AesShared tb; tb.Td0=sTd0; tb.Td1=sTd1; tb.Td2=sTd2; tb.Td3=sTd3; tb.sbox=sS; tb.isbox=sIS;

    const int      L  = c_pw_len;
    const uint32_t n0 = c_n0;
    const uint64_t stride = (uint64_t)gridDim.x * blockDim.x;

    for (uint64_t base = base_begin + (uint64_t)blockIdx.x * blockDim.x + threadIdx.x;
         base < base_begin + base_count; base += stride)
    {
        if (d_res.found) return;

        // decode mask positions 1..L-1 from the base index (position 0 varies in the inner loop)
        uint8_t pw[MB_MAX_LEN];
        uint64_t x = base;
        #pragma unroll 1
        for (int i = 1; i < L; i++) {
            uint32_t k = c_cs_len[i];
            pw[i] = c_cs_data[c_cs_off[i] + (uint32_t)(x % k)];
            x /= k;
        }
        pw[0] = 0;

        // hoist: build key1's MD5 message once; only M[0]'s low byte changes per inner step.
        uint32_t M1[16];
        d_md5_buildM(pw, L, c_salt, 8, nullptr, 0, M1);
        const uint32_t M0base = M1[0] & 0xffffff00u;

        for (uint32_t c0 = 0; c0 < n0; c0++) {
            const uint8_t ch = c_cs_data[c_cs0_off + c0];
            pw[0] = ch;
            M1[0] = M0base | ch;                 // pw[0] == message byte 0 == low 8 bits of M[0]

            uint8_t d1[16];
            d_md5_compress(M1, d1);              // key1

            int k = dev_finish_from_key1(d1, c_salt, c_data, pw, L, tb);
            if (k) {
                const uint64_t idx = base * (uint64_t)n0 + c0;
                if (atomicCAS(&d_res.found, 0, 1) == 0) {
                    d_res.index = idx; d_res.kind = k;
                    for (int i = 0; i < L; i++) d_res.pw[i] = pw[i];
                }
                return;
            }
        }
    }
}

// ---- host launcher ----
static void upload_tables() {
    AesTd t; aes_build_tables(t);
    cudaMemcpyToSymbol(g_Td0, t.Td0, sizeof(t.Td0));
    cudaMemcpyToSymbol(g_Td1, t.Td1, sizeof(t.Td1));
    cudaMemcpyToSymbol(g_Td2, t.Td2, sizeof(t.Td2));
    cudaMemcpyToSymbol(g_Td3, t.Td3, sizeof(t.Td3));
    cudaMemcpyToSymbol(g_sbox, t.sbox, 256);
    cudaMemcpyToSymbol(g_isbox, t.isbox, 256);
}

CrackResult cuda_crack(const Target& t, const Mask& m,
                       uint64_t skip, uint64_t count, int device_id)
{
    CrackResult out;
    cudaError_t err = cudaSetDevice(device_id);
    if (err != cudaSuccess) { fprintf(stderr, "cudaSetDevice: %s\n", cudaGetErrorString(err)); return out; }

    cudaDeviceProp prop; cudaGetDeviceProperties(&prop, device_id);
    printf("device: %s  sm_%d%d  SMs=%d\n", prop.name, prop.major, prop.minor, prop.multiProcessorCount);

    const int L = m.length();
    if (L < 1 || L > MB_MAX_LEN) { fprintf(stderr, "mask length %d out of range\n", L); return out; }

    // flatten per-position charsets
    std::vector<uint8_t> cs_data;
    uint32_t cs_off[MB_MAX_LEN], cs_len[MB_MAX_LEN];
    for (int i = 0; i < L; i++) {
        cs_off[i] = (uint32_t)cs_data.size();
        cs_len[i] = (uint32_t)m.pos[i].size();
        for (char c : m.pos[i]) cs_data.push_back((uint8_t)c);
    }
    if (cs_data.size() > MB_MAX_CS) { fprintf(stderr, "flattened charset too big (%zu)\n", cs_data.size()); return out; }

    const uint32_t n0 = cs_len[0];
    const uint32_t cs0_off = cs_off[0];

    upload_tables();
    cudaMemcpyToSymbol(c_salt, t.salt, 8);
    cudaMemcpyToSymbol(c_data, t.data, 32);
    cudaMemcpyToSymbol(c_cs_data, cs_data.data(), cs_data.size());
    cudaMemcpyToSymbol(c_cs_off, cs_off, sizeof(uint32_t) * L);
    cudaMemcpyToSymbol(c_cs_len, cs_len, sizeof(uint32_t) * L);
    cudaMemcpyToSymbol(c_pw_len, &L, sizeof(int));
    cudaMemcpyToSymbol(c_n0, &n0, sizeof(uint32_t));
    cudaMemcpyToSymbol(c_cs0_off, &cs0_off, sizeof(uint32_t));

    DevResult init; memset(&init, 0, sizeof(init));
    cudaMemcpyToSymbol(d_res, &init, sizeof(init));

    // idx-space [skip, skip+count) -> base-space, rounded OUT to whole bases (n0 boundary).
    // Over-covers <= n0-1 candidates at each end (harmless for a cracker); note it in output.
    const uint64_t base_begin = skip / n0;
    const uint64_t base_end   = (skip + count + n0 - 1) / n0;
    const uint64_t n_base     = base_end - base_begin;

    // grid-stride; each launch a chunk of bases so a launch stays sub-second (TDR watchdog).
    const uint64_t BASE_CHUNK = 1ull << 22;                 // 4M bases/launch (x n0 candidates)
    const int block = MB_THREADS;
    const int grid  = prop.multiProcessorCount * 32;

    for (uint64_t done = 0; done < n_base; done += BASE_CHUNK) {
        const uint64_t this_bases = std::min<uint64_t>(BASE_CHUNK, n_base - done);
        crack_kernel<<<grid, block>>>(base_begin + done, this_bases);
        err = cudaDeviceSynchronize();
        if (err != cudaSuccess) { fprintf(stderr, "kernel: %s\n", cudaGetErrorString(err)); break; }

        DevResult r; cudaMemcpyFromSymbol(&r, d_res, sizeof(r));
        if (r.found) {
            out.found = true; out.index = r.index; out.kind = r.kind; out.pw_len = L;
            for (int i = 0; i < L; i++) out.pw[i] = r.pw[i];
            break;
        }
        printf("  ...%.1f%%\r", 100.0 * (double)(done + this_bases) / (double)n_base);
        fflush(stdout);
    }
    return out;
}

} // namespace mb
