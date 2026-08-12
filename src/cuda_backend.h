// cuda_backend.h — interface implemented by kernel.cu (built with nvcc).
// main.cpp calls this only when compiled with -DUSE_CUDA.
#pragma once
#include <cstdint>
#include "pipeline_ref.h"
#include "mask.h"

namespace mb {

struct CrackResult {
    bool     found = false;
    uint64_t index = 0;
    uint8_t  pw[32] = {0};
    int      pw_len = 0;
    int      kind = 0; // WalletKind
};

// Brute-force [skip, skip+count) of the mask keyspace on the GPU.
// Returns as soon as a hit is found (or the range is exhausted).
CrackResult cuda_crack(const Target& t, const Mask& m,
                       uint64_t skip, uint64_t count,
                       int device_id);

} // namespace mb
