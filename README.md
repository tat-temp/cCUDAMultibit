# mbcrack — MultiBit Classic `.key` password cracker (hashcat m22500, native CUDA)

Custom-charset (mask) brute-forcer for **MultiBit Classic `.key` (MD5)** wallets — the algorithm
of hashcat kernel mode **22500**, reimplemented as a standalone CUDA/C++ app targeting the **RTX 5090
(`sm_120`)**. See [`DEVELOPMENT_PLAN.md`](DEVELOPMENT_PLAN.md) for the full algorithm extraction and design.

## Status

| component | state |
|---|---|
| Algorithm extraction (MD5×3 KDF + AES-256-CBC + structural checks) | ✅ documented + **validated** |
| CPU reference (`src/*_ref.h`, `pipeline_ref.h`) | ✅ builds with g++, passes KATs + self-test |
| Mask engine (custom charsets, index↔password) | ✅ CPU-validated |
| CLI (`mbcrack`, multithreaded CPU backend) | ✅ works today |
| **Phase-6 GPU backend** (T-table AES in shared mem, a3 amplifier, hoisted key1, `__launch_bounds__`) | ✅ logic bit-identical to CPU ref **+ compiles & links for `sm_120` under real nvcc (CUDA 13.0)** |
| Further tuning (register/occupancy sweep, MD5 pre-add hoist) | ⬜ requires on-hardware Nsight profiling |

### Phase-6 validation
**(a) Numerical — via CUDA-qualifier stubs on the CPU, no GPU:**
- T-table AES-256 decrypt == golden byte-oriented AES on **100,000 random vectors** + FIPS-197 C.3.
- Full kernel path (T-table AES + hoisted key1 + amplifier index math) == CPU reference on **all 676**
  candidates of a two-axis test mask; recovers `hashcat` at the correct keyspace index, **0 mismatches**.

**(b) Toolchain — real `nvcc` (CUDA 13.0.88) targeting `sm_120`, WSL2 Ubuntu, no GPU present:**
- `make GPU_ARCH=120` compiles `main.cpp` + `kernel.cu` and links `mbcrack` (static cudart); `sm_120`
  cubin confirmed via `cuobjdump -lelf`. `crack_kernel`: **128 reg, 5632 B smem, 1 barrier**.
- On a driverless host the backend now **fails loudly** (`cudaSetDevice` error → exit 3, no false verdict).
- Only kernel *execution* remains unexercised — that needs an actual `sm_120` GPU.

The register/occupancy tradeoff (block=256, spills disappear only at 1 block/SM) is tabulated in
[`DEVELOPMENT_PLAN.md`](DEVELOPMENT_PLAN.md) as the starting matrix for on-hardware tuning.

## Build & run — CPU (works now, no CUDA required)

```bash
# with the provided CMake
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release
ctest --test-dir build            # runs the self-test

# or directly with g++
g++ -O3 -std=c++17 -Isrc test/selftest.cpp -o selftest && ./selftest
g++ -O3 -std=c++17 -Isrc -pthread src/main.cpp -o mbcrack
```

Self-test vector (from the hashcat module) — password is `hashcat`:

```
./mbcrack '$multibit$1*e5912fe5c84af3d5*5f0391c219e8ef62c06505b1f6232858f5bcaa739c2b471d45dd0bd8345334de' -a 3 'hashc?l?l'
# -> CRACKED: index=494  password="hashcat"  wallet=MultiBit Classic
```

Custom charset example (`?1` = your set):

```
./mbcrack wallet.hash -a 3 '?1?1?1?1?1?1' -1 abcdefghijklmnopqrstuvwxyz0123456789
```

Options: `-a 3 <mask>`, `-1..-4 <chars>` custom sets, `--skip N`, `--limit N`, `-j <threads>`, `-d <gpu>`.
Built-in charsets in masks: `?l ?u ?d ?s ?a`.

## Test-vector generator (`gen_vector`)

The inverse of the crack pipeline — *encrypts* a chosen plaintext under a password to emit a
`$multibit$1*…` line, so you can produce known-answer wallets for any of the three header types.
Every vector is self-verified by running it back through the validated cracker before it's printed.

```bash
make gen_vector                                   # or: g++ -O2 -std=c++17 -Isrc tools/gen_vector.cpp -o gen_vector
./gen_vector --pass hunter2 > wallet.hash         # MultiBit Classic (base58), stdout = clean hash line
./gen_vector --pass s3cret --type bitcoinj        # also: --type knc
./gen_vector --pass p@ss --salt 0011223344556677  # fixed salt (default: deterministic from password)
./gen_vector --selftest                           # FIPS KAT + encrypt==inverse-of-decrypt + gen→crack ×3
./gen_vector --suite ./vectors                    # labelled regression suite + INDEX.tsv
```

Proven closed loop (all run on CPU here): `gen_vector --type {multibit,bitcoinj,knc}` → `mbcrack`
recovers the exact password with the correct wallet type; a wrong charset exhausts with no false
positive. `encrypt(decrypt(ST_HASH)) == ST_HASH` confirms encrypt is the exact inverse of the
validated decrypt on the real self-test vector.

## Build & run — GPU (RTX 5090)

Requires **NVIDIA driver + CUDA Toolkit ≥ 12.8** (first native `sm_120` support). On **Windows** nvcc uses
**MSVC** as host compiler; for a **g++** host toolchain build under **Linux/WSL2**.

**Ubuntu / Linux (Makefile):**
```bash
make                 # GPU build -> ./mbcrack   (auto-detects arch; RTX 5090 = sm_120)
make GPU_ARCH=120    # if nvidia-smi isn't on PATH
make gate            # ptxas register/spill report for the hot kernel (run before benchmarking)
make cpu             # CPU-only build + selftest, no CUDA needed
```

**CMake (cross-platform):**
```bash
cmake -S . -B build-cuda -DUSE_CUDA=ON -DCMAKE_BUILD_TYPE=Release && cmake --build build-cuda
```

## Benchmark throughput (GPU)

`--benchmark` runs the real kernel over a synthetic, non-matching target so every guess takes the full
per-candidate path (MD5 key1 + AES first block + early-skip) — i.e. the cost of an exhaustive search. It
times **only** the kernel via CUDA events (device init, table upload, and JIT happen in an excluded
warm-up) and prints GH/s:

```bash
./mbcrack --benchmark               # ~2e9 guesses (default), fixed reproducible mask
```
```bash
./mbcrack --benchmark 8000000000 -d 0   # pick guess count and GPU
```

Compare against hashcat on the same card with `hashcat -b -m 22500`. Throughput is mask-dependent, so the
benchmark pins a fixed mask (L=8, 64-symbol set); report the number next to the card.

**Occupancy/register tuning** — the `__launch_bounds__(256, N)` knob (spills vs occupancy; see the matrix
in [`DEVELOPMENT_PLAN.md`](DEVELOPMENT_PLAN.md)). Changing it needs a clean rebuild:

```bash
make clean && make MINBLOCKS=1 && ./mbcrack --benchmark
```

`N=1` removes spills at low occupancy, `N=2` (default) is the middle, `N=3` maximizes occupancy with heavy
spills — pick the winner by measured GH/s. `make gate MINBLOCKS=N` reports the matching register ceiling.

## Layout

```
DEVELOPMENT_PLAN.md   full analysis + roadmap
src/md5_ref.h         CPU MD5 (reference)          src/md5.cuh      device MD5 (single-block)
src/aes_ref.h         CPU AES-256 (reference)      src/aes.cuh      device AES-256
src/verify.h          structural predicates (shared host/device)
src/pipeline_ref.h    CPU per-candidate pipeline   src/pipeline.cuh device pipeline (1:1 mirror)
src/mask.h            custom-charset mask engine
src/main.cpp          CLI + CPU backend            src/kernel.cu    CUDA backend + launcher
test/selftest.cpp     KATs + end-to-end self-test
```

## Scope / ethics

For recovering **your own** wallet password (or authorized testing). MultiBit Classic is long
discontinued; users who lost access to their own `.key` files are the intended audience.
