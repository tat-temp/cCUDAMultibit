# MultiBit `m22500` → Native CUDA cracker for RTX 5090

**Goal:** a standalone CUDA/C++ application that brute-forces a MultiBit Classic `.key`
password from a user-supplied **custom charset / mask**, replicating hashcat kernel mode
**22500** (`MultiBit Classic .key (MD5)`) without OpenCL/hashcat runtime.

Source analyzed (hashcat `master`):
- `OpenCL/m22500_a0-optimized.cl`, `m22500_a1-optimized.cl`, `m22500_a3-optimized.cl`
- `OpenCL/m22500_*-pure.cl` (clearest reference)
- `src/modules/module_22500.c` (format / salt layout)
- `OpenCL/inc_common.cl` (`is_valid_base58_*`), `inc_cipher_aes.cl`, `inc_hash_md5.cl`

---

## PART 1 — Algorithm extraction

### 1.1 Input format

Hash line (from `module_hash_decode`):

```
$multibit$1*<salt: 8 bytes hex>*<data: 32 bytes hex>
        sig  ^ver  ^16 hex chars    ^64 hex chars
```

- `version` must be `1`.
- `salt`  = 8 bytes  → `salt_buf[0..1]`
- `data`  = 32 bytes → `salt_buf[2..9]` (this is the first **two** AES-CBC ciphertext blocks
  of the encrypted wallet file, i.e. the OpenSSL `Salted__`-style body without the header).
- `salt_len = 40` (8 + 32).

**Byte order (critical for a correct port).** hashcat's `hex_to_u32` packs the hex so that the
resulting `u32`, interpreted **little-endian**, reproduces the original byte sequence. MD5 here is
fed little-endian (`OPTS_TYPE_PT_GENERATE_LE`), and AES consumes the same words. Net effect:

> Parse hex → **raw bytes in file order**. Load as little-endian `u32`. On x86-64 and CUDA
> (both little-endian) **no swapping is needed anywhere** in the KDF or AES. Validate against the
> self-test vector (§4.6) before trusting anything.

Self-test vector (from the module): password `hashcat` ⇒
`$multibit$1*e5912fe5c84af3d5*5f0391c219e8ef62c06505b1f6232858f5bcaa739c2b471d45dd0bd8345334de`

### 1.2 The KDF + verification pipeline (per candidate password `P`)

This is the whole hot loop. `salt` = 8 bytes, `data[0..7]` = 32 ciphertext bytes (two 16-byte blocks
`C0 = data[0..3]`, `C1 = data[4..7]`).

```
key1 = MD5( P || salt )                 // 16 bytes
key2 = MD5( key1 || P || salt )         // 16 bytes
iv   = MD5( key2 || P || salt )         // 16 bytes

ukey = key1 || key2                     // 32-byte AES-256 key
                                        // OpenSSL EVP_BytesToKey(MD5, count=1): 48 bytes = key(32)+iv(16)

ks   = AES256_setup_decrypt_key(ukey)   // equivalent-inverse-cipher round keys (14 rounds)

// --- CBC block 0 ---
out  = AES256_decrypt_block(ks, C0)
out ^= iv                               // plaintext block P0 (16 bytes)

first_byte = out[0] & 0xff
if first_byte not in {0x4b 'K', 0x4c 'L', 0x51 'Q', 0x35 '5', 0x23 '#', 0x0a '\n'}:
    reject                              // <-- ~253/256 candidates die here (EARLY_SKIP)
```

Only survivors continue to the structural check (§1.3). The **AES-256 key is different for every
candidate**, so the key schedule cannot be precomputed — it is part of the per-candidate cost.

`OpenSSL EVP_BytesToKey` chaining note: `key1|key2` = 32-byte key, and `iv` = next 16 bytes of the
same MD5 chain. MultiBit derives all three with the classic salted-MD5 stretch, count = 1.

### 1.3 Plaintext-structure verification (replaces a real digest)

m22500 has **no stored digest** — `module_hash_decode` puts the ciphertext into the "digest" slots as a
placeholder. A hit is decided purely by whether the decrypted plaintext looks like a known wallet
header. Four accepted shapes, keyed on `first_byte`:

| first byte | wallet type | check |
|---|---|---|
| `K`/`L`/`Q`/`5` | MultiBit Classic (base58 WIF privkey) | all 16 bytes of P0 are base58; decrypt C1, XOR C0, all 16 bytes base58 |
| `\n` (0x0a) | bitcoinj | bytes match `"\norg.…"` (`org.` at offset 2) + `is_valid_bitcoinj_8` on bytes 6..13 |
| `#` (0x23) | KnCGroup | P0 == `"# KEEP YOUR PRIV"`; decrypt C1, XOR C0 ⇒ `"ATE KEYS SAFE! A"` |

Charset predicates (exact, from `inc_common.cl`):

```c
// base58: '1'..'9','A'..'H','J'..'N','P'..'Z','a'..'k','m'..'z'  (no 0 O I l)
is_valid_base58_8(v): '1'<=v<='z', excluding '0'(<'1'), ':'..'@', '['..'`', and 'O','I','l'
// bitcoinj tail: '.' and 'a'..'z' only
is_valid_bitcoinj_8(v): v=='.' or 'a'<=v<='z'
```

The KnCGroup/bitcoinj literals in the kernel are byte-swapped `u32` compares (e.g. `0x454b2023` = `"# KE"`);
in a native LE port compare against the ASCII words directly.

**For a targeted MultiBit password recovery you normally only need the `K/L/Q/5` (base58) branch** — but
port all four; they cost nothing on the rejected path and prevent false negatives.

### 1.4 Why `pw_max = 31` (the single-block MD5 property)

`module_pw_max` returns 31 for the optimized kernels: `55 − 8 (salt) − 16 (prev key) = 31`. Consequences,
which the `-optimized` kernels exploit and your port should too:

- `MD5(P||salt)`      : ≤ 31 + 8  = 39 bytes  → **1 MD5 block**
- `MD5(key1||P||salt)`: ≤ 16+31+8 = 55 bytes  → **1 MD5 block** (55 is the max that still fits with padding)
- `MD5(key2||P||salt)`: ≤ 55 bytes            → **1 MD5 block**

So the KDF is exactly **three 64-byte MD5 compressions**, no loops. This is the single most important
performance property. (If you ever need passwords > 31, you fall back to a multi-block MD5 like the
`-pure` kernels and lose this; keep the 31-char fast path as the default.)

### 1.5 Per-candidate cost model

Rejected path (≈97.7% of candidates): `3× MD5 compression + 1× AES-256 key expansion + 1× AES-256 block
decrypt + 1 byte test`. The rare survivors add a second AES decrypt and the byte-wise structural checks.
**Throughput is governed by the rejected path.** Rough op budget per candidate:

- MD5: 3 × 64 steps = 192 rounds of ADD/ROTL/bool.
- AES-256 decrypt key schedule: 14-round expansion + InvMixColumns on rounds 1..13 (T-table lookups).
- AES-256 decrypt: 14 rounds × 16 T-table (`td0..td4`) lookups.

The **AES key schedule + one decrypt dominate** over the three single-block MD5s. Optimizing AES on
Blackwell is where the wins are (§2.5).

### 1.6 Candidate generation — what differs between a0 / a1 / a3

The crypto in §1.2–1.3 is **byte-identical** across `a0`, `a1`, `a3`. Only how `P` is produced differs:

| mode | name | candidate source | relevance |
|---|---|---|---|
| `a0` | straight | host wordlist, per-word rules applied on device (`apply_rules`) | dictionary attacks |
| `a1` | combinator | `P = pws[gid] (left) ⧺ combs_buf[il] (right)`, concatenated on device | two wordlists |
| **`a3`** | **brute-force / mask** | **on-device charset expansion** | **your target** |

**The a3 brute-force amplifier (this is "bruteforce by custom charset").** hashcat does not send every
candidate over PCIe. It splits the mask into a *base* part and a *right/amplifier* part:

- `pws[gid]` holds the base word bytes for this work-item, with **`w[0]`'s low bytes left open**.
  `w0l = w[0]` is the base contribution.
- `words_buf_r[]` (device buffer, length `IL_CNT`) holds the pre-expanded values of the **last mask
  position(s)** — one entry per symbol of the rightmost charset.
- The inner loop fuses them:

```c
u32 w0l = w[0];
for (u32 il_pos = 0; il_pos < IL_CNT; il_pos += VECT_SIZE) {
    u32x w0r = words_buf_r[il_pos / VECT_SIZE];   // rotating last char(s)
    u32x w0  = w0l | w0r;                          // full candidate word[0]
    ... run KDF+AES with this w0 ...
}
```

So each GPU thread runs the full pipeline `IL_CNT` times, changing only the last charset position(s).
This **amortizes the per-thread setup** (salt load, the `F_*`/`G_*`/`H_*`/`I_*` MD5 message-constant
pre-adds computed once before the loop) across the whole rightmost charset. The `-optimized` kernel also
**pre-adds the round-constant + message word** for the first MD5 (`F_w1c01 = w[1] + MD5C01`, …) *outside*
the loop, and hoists the salt into the padded `w[]` via `switch_buffer_by_offset_le_S` — because only
`w[0]` changes inside the loop. That is the structural trick you re-create in CUDA (§2.2).

`VECT_SIZE` is the SIMD width (hashcat vectorizes 1/2/4/…). On NVIDIA you keep `VECT_SIZE = 1` and rely on
thread-level parallelism instead.

The `m04/m08/m16` (and `s04/s08/s16`) variants just correspond to how many `w[]` registers the base word
occupies (≤16 / ≤32 / ≤64 bytes); `m*` = multi-hash (bitmap), `s*` = single-hash. For a single target
wallet you only need one variant.

---

## PART 2 — Native CUDA design for RTX 5090

### 2.1 Target hardware

- **RTX 5090 = GB202, Blackwell, compute capability 12.0 → `sm_120`.** 170 SMs, 21,760 CUDA cores,
  32 GB GDDR7 (512-bit, ~1.79 TB/s).
- **Requires CUDA Toolkit ≥ 12.8** for native `sm_120` codegen (13.x also fine). Building with an older
  toolkit will PTX-JIT at best or fail; do not target `sm_90`/`sm_100` (those are Hopper / datacenter
  Blackwell, not this GPU).
- This is a **compute/ALU-bound** workload, not memory-bound. HBM bandwidth is irrelevant to the hot
  loop; occupancy, register pressure, and the AES T-table access pattern are what matter.

### 2.2 Candidate generation: generate the whole space **on-device** (recommended)

Do **not** copy candidates over PCIe. A purpose-built cracker maps a **global 64-bit index → password**
inside the kernel via mixed-radix (little-endian, hashcat "keyspace" order) decode over the per-position
charsets. This removes the host bottleneck entirely and is simpler than hashcat's split buffers.

Given a mask of `L` positions, each position `i` with charset `cs[i]` of size `n[i]`, total keyspace
`N = Π n[i]`:

```c
// device: candidate index -> password bytes (little-endian position order, like hashcat masks)
__device__ void index_to_password(uint64_t idx,
                                  const uint8_t* d_charsets,   // packed
                                  const uint32_t* d_cs_off,    // offset of each position's charset
                                  const uint32_t* d_cs_len,    // size of each position's charset
                                  int pw_len,
                                  uint8_t out[32]) {
    for (int i = 0; i < pw_len; i++) {
        uint32_t n = d_cs_len[i];
        uint32_t r = (uint32_t)(idx % n);
        idx /= n;
        out[i] = d_charsets[d_cs_off[i] + r];
    }
}
```

Then keep hashcat's amortization idea: launch one thread per *base* index (positions `1..L-1`) and loop
the **innermost position 0** (or the last, whichever you fix) inside the thread so the message-constant
pre-adds and salt packing are hoisted out of the inner loop. Concretely:

- Grid stride over `base = idx / n[0]`.
- Precompute `w[1..15]` (base word + salt + length padding) and all `F_/G_/H_/I_` pre-adds once.
- Inner `for (c = 0; c < n[0]; c++) { w0 = base_w0 | charset0[c]; run_pipeline(); }`.

This reproduces the a3 speed structure without any host candidate buffers.

Chunking: split `N` into launches of, say, 2^30–2^32 candidates so a single kernel stays < a few seconds
(keeps the OS/driver watchdog happy and gives responsive progress/ETA and checkpointing).

### 2.3 Kernel pipeline (one device function, mirrors §1.2)

```
run_pipeline(w0, w[1..], salt-packed, C0, C1):
    key1 = md5_block(w with w[0]=w0)                 // hoist F_/G_/H_/I_ pre-adds, only w0 varies
    key2 = md5_block(key1 || pw || salt)             // second single block
    iv   = md5_block(key2 || pw || salt)             // third single block
    ks   = aes256_expand_dec_key(key1||key2)
    p0   = aes256_dec(ks, C0) ^ iv
    b    = p0 & 0xff
    if b not in {K,L,Q,5,#,\n}: return               // EARLY_SKIP
    ... structural checks (§1.3), report hit via atomic + global result slot ...
```

Reuse hashcat's math exactly:
- **MD5**: port `MD5_STEP`/`MD5_Fo/Go/H/I` and constants from `inc_hash_md5.cl`. Keep the pre-add
  hoist for the first block (only `w0` changes across the inner loop).
- **AES-256**: port `aes256_set_decrypt_key` + `aes256_decrypt` + tables `te0..te4`, `td0..td4`
  from `inc_cipher_aes.cl`. These are the standard 4×256×4B T-tables.

### 2.4 Memory layout

- **AES T-tables → shared memory**, staged once per block from `__constant__`/`__device__` at kernel entry
  (exactly hashcat's `REAL_SHM` path: 10 tables × 256 × 4 B = **10 KB**). On `sm_120` you have up to
  228 KB shared/SM — 10 KB is trivial; this keeps table lookups off the L2 path and avoids bank conflicts
  becoming global-memory stalls. Consider replicating tables to reduce 32-way bank conflicts, or measure
  the constant-memory path (`td0..td4` in `__constant__`) which broadcasts well when the index is uniform
  — but AES indices are data-dependent, so **shared is the safe default**.
- **salt (8 B), C0/C1 (32 B), mask/charset tables** → `__constant__` memory (read-only, broadcast).
- **result** → a small `__device__` struct `{int found; uint64_t index; uint8_t pw[32];}` updated under
  `atomicCAS`/`atomicExch` on the (rare) hit. No per-candidate global writes.
- Keep everything else in registers. Watch register pressure: MD5 (a,b,c,d) + AES `ks[60]` + `out[4]`.
  `ks[60]` is 240 B of registers/local — this is the pressure hotspot; see §2.5.

### 2.5 Bottlenecks & Blackwell-specific optimizations

1. **AES key schedule per candidate is the dominant cost.** `ks[60]` risks spilling to local memory.
   Options, in order:
   - Compute the schedule into registers and *immediately* consume it in the single decrypt; don't keep
     it live across MD5. Reorder so MD5 (key derivation) fully retires before AES starts.
   - Use the **non-equivalent inverse cipher** (forward-ordered key schedule + on-the-fly InvMixColumns)
     to avoid the InvMixColumns pass over 13 round keys in `set_decrypt_key`. Benchmark both.
   - Since only 1 decrypt block is needed on the reject path, minimize schedule work: you need all 15
     round keys, but you can fuse expansion with the first rounds.
2. **T-table lookups**: 16 lookups/round × 14 rounds. Put tables in shared; test `td4`-only last round.
   Measure bank-conflict impact with Nsight Compute; if severe, pad tables to 257 or replicate per-warp.
3. **Occupancy vs registers**: target ≥ 2–3 blocks/SM. Use `-maxrregcount` or `__launch_bounds__` to cap
   registers and prevent `ks` spills from destroying occupancy. Sweep block size {128,192,256}.
4. **Inner-loop hoist** (§2.2): compute the three MD5 message-constant pre-adds and salt packing once per
   base word. This is a real, measurable win — it's why the `-optimized` kernels exist.
5. **No `__syncthreads` in the hot loop** (only once, after staging tables).
6. **Two-phase / early-skip friendliness**: the `first_byte` test kills 253/256. Keep the structural
   checks after it so divergence is confined to ~1% of threads.
7. **Blackwell**: 5th-gen tensor cores are useless here (integer bit-twiddling), but Blackwell's improved
   integer throughput and larger register file help. Compile with `-arch=sm_120 --use_fast_math` (fast_math
   is irrelevant — no FP — but harmless), and profile with **Nsight Compute** for `sm_120`.

### 2.6 Throughput expectation (order-of-magnitude — must be benchmarked)

m22500 is a *fast* hash. As a reference point, plain MD5 (mode 0) runs at tens–hundreds of GH/s on
top-end GPUs; m22500's 3×MD5 + AES key-expand + AES decrypt puts it roughly **~2–3 orders slower than
raw MD5**. Expect the RTX 5090 to land in the **low-single-digit GH/s** range for a tight native kernel,
i.e. broadly comparable to (and ideally a bit above) hashcat's own m22500 on the same GPU. **Treat this as
a hypothesis to validate** — do not quote a number until you've measured on hardware. A useful ceiling
check: profile the AES-decrypt-only and MD5-only kernels separately, then the fused one.

---

## PART 3 — Toolchain & build (the `g++` question, honestly)

You asked for CUDA **and** g++. Important platform reality:

- **On Windows, `nvcc` requires MSVC (`cl.exe`) as the host compiler.** MinGW/MSYS2 `g++` is **not** a
  supported host compiler for `.cu` files on Windows and will not work with the CUDA runtime headers/libs.
  You have **VS 2022** installed (`C:\Program Files\Microsoft Visual Studio\2022`) — that is the correct
  host compiler here. CUDA 12.8/13.x supports VS 2022 (17.x).
- **`g++` as host compiler is fully supported on Linux (and WSL2).** If you specifically want the g++
  toolchain, build under **WSL2 Ubuntu** or native Linux with the NVIDIA driver + CUDA toolkit; there
  `nvcc -ccbin g++` is the standard path.

Recommended split:
- **Windows-native:** `nvcc` + MSVC for the whole app (device + host). Your MSYS2 `g++ 16.1` is fine for
  *unit-testing the pure-C++ reference implementation* of MD5/AES/mask on CPU, but not for the CUDA build.
- **If g++ is a hard requirement for the whole build:** use **WSL2** (`nvcc -ccbin g++-13`). Same source,
  same kernels.

**You currently have no CUDA toolkit and no NVIDIA driver visible** (`nvcc` and `nvidia-smi` not found).
First actionable step is installing them (§4, Phase 0).

### 3.1 CMake (cross-platform, picks MSVC or g++ automatically)

```cmake
cmake_minimum_required(VERSION 3.24)
project(mbcrack LANGUAGES CXX CUDA)

set(CMAKE_CUDA_ARCHITECTURES 120)          # RTX 5090 = sm_120 (needs CUDA >= 12.8)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CUDA_STANDARD 17)

add_executable(mbcrack
    src/main.cpp          # CLI, hash-line parse, mask parse, orchestration
    src/mask.cpp          # keyspace / index math (host, testable with g++)
    src/kernel.cu)        # device pipeline + launch

target_compile_options(mbcrack PRIVATE
    $<$<COMPILE_LANGUAGE:CUDA>:-lineinfo --ptxas-options=-v -maxrregcount=96>)
# add __launch_bounds__ in code rather than relying only on maxrregcount
```

Configure/build:
```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release -j
```

### 3.2 Linux/WSL2 Makefile (explicit g++ host compiler)

```make
NVCC   = nvcc
CXX    = g++
ARCH   = -gencode arch=compute_120,code=sm_120
CXXFLAGS = -O3 -std=c++17
NVFLAGS  = -O3 -std=c++17 $(ARCH) -ccbin $(CXX) --ptxas-options=-v -lineinfo

mbcrack: main.o mask.o kernel.o
	$(NVCC) $(NVFLAGS) $^ -o $@
kernel.o: src/kernel.cu
	$(NVCC) $(NVFLAGS) -c $< -o $@
%.o: src/%.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@
```

---

## PART 4 — Project structure & milestones

```
multibit/
├─ DEVELOPMENT_PLAN.md      (this file)
├─ CMakeLists.txt
├─ Makefile                 (Linux/WSL2, g++ host)
├─ src/
│  ├─ main.cpp              CLI, parse $multibit$ line, parse mask, chunking, progress/ETA, checkpoint
│  ├─ mask.hpp / mask.cpp   charset table build, keyspace = Π n[i], index<->password (host + shared w/ device)
│  ├─ md5.cuh               device MD5 (single-block, pre-add hoist)  — ported from inc_hash_md5.cl
│  ├─ aes.cuh               device AES-256 T-tables + set_decrypt_key + decrypt — from inc_cipher_aes.cl
│  ├─ pipeline.cuh          run_pipeline() = KDF + AES + structural checks (§1.2/1.3)
│  ├─ kernel.cu             __global__ crack_kernel(), launch config, __constant__ salt/data/charset
│  └─ verify.hpp            structural predicates (base58, bitcoinj, KnC literals)
├─ test/
│  ├─ ref_cpu.cpp           pure-C++ reference of the full pipeline (build with g++, no CUDA)
│  └─ selftest.cpp          asserts password "hashcat" cracks the ST_HASH vector
└─ tools/
   └─ make_test_wallet.py   optional: encrypt a known wallet to generate more vectors
```

### Milestones (each ends with a hard validation gate)

- **Phase 0 — Environment.** Install NVIDIA driver + **CUDA Toolkit ≥ 12.8**. Confirm `nvcc --version`
  and `nvidia-smi` show the 5090 as `sm_120`. Build/run the CUDA `deviceQuery` sample. *(You are here —
  toolkit/driver currently absent.)*
- **Phase 1 — CPU reference (correctness first, no GPU).** In plain C++ (compile with your `g++ 16.1`):
  implement the §1.2 pipeline using any MD5/AES (even OpenSSL) and reproduce the self-test:
  `crack("$multibit$1*e591…34de") over charset` finds `hashcat`. **Gate:** self-test passes bit-exact.
- **Phase 2 — Device MD5.** Port single-block MD5 to `md5.cuh`; unit-test against CPU for the three KDF
  calls. **Gate:** device `key1/key2/iv` == CPU for the test password.
- **Phase 3 — Device AES-256.** Port T-tables + `set_decrypt_key` + `decrypt`; test one CBC block against
  CPU/OpenSSL. **Gate:** `AES_dec(ks,C0)^iv` matches CPU.
- **Phase 4 — Fused kernel, brute-1-position.** Assemble `run_pipeline`; kernel that scans a tiny mask
  (e.g. `hashca?l` → last char) and finds `hashcat`. **Gate:** self-test found on GPU; result index &
  reconstructed password correct.
- **Phase 5 — On-device mask engine.** Mixed-radix `index_to_password`, arbitrary custom charsets
  (`-1 abc…`, per-position charsets), inner-loop hoist (§2.2), 64-bit keyspace, chunked launches,
  progress/ETA, `--skip`/`--limit` checkpoint-resume. **Gate:** end-to-end recovery of a known password
  from a real/synthetic `.key`.
- **Phase 6 — Optimize.** ✅ *Implemented & logic-validated.* Delivered: (1) AES-256 **T-tables in shared
  memory** (`aes.cuh`, staged once/block), (2) the **a3 amplifier** — one thread per base word, inner loop
  over the fastest charset position (`kernel.cu`), (3) **hoisted key1** MD5 message assembly per base,
  (4) `__launch_bounds__(256,2)` + single `__syncthreads`. Validated bit-identical to the CPU reference via
  qualifier stubs (T-table AES over 100k vectors; full kernel path over a 676-candidate two-axis mask,
  0 mismatches). `make gate` surfaces the ptxas register/spill numbers. **Remaining (needs hardware):**
  Nsight Compute register/occupancy sweep, `ks/dk[60]` spill vs stack-frame decision, block-size sweep,
  bank-conflict check → then **Gate:** documented GH/s, ≥ hashcat m22500 on the same 5090.
- **Phase 7 — Hardening (optional).** Multi-GPU, multiple wallets in one pass, mask files / `?d?l?u?s`
  built-ins, `.hcmask` compatibility, keyspace distribution across machines.

### 4.6 Self-test that must pass at every phase

```
hash : $multibit$1*e5912fe5c84af3d5*5f0391c219e8ef62c06505b1f6232858f5bcaa739c2b471d45dd0bd8345334de
pass : hashcat
```
Feed it a mask that contains `hashcat` in its keyspace and confirm the exact index + reconstructed
password are returned, and that `first_byte` for the correct password is one of `{K,L,Q,5,#,\n}` followed
by passing the base58 (or matching) structural check.

---

## PART 5 — Gotchas / correctness checklist

- **Endianness:** parse hex → raw bytes; MD5/AES consume little-endian words; on x86-64 + CUDA no swaps.
  Verify with the self-test before optimizing anything.
- **`pw_max = 31`** for the single-block fast path. If you must support longer, add a multi-block MD5 path
  (see `-pure` kernels) — but keep 31 as the default fast path.
- **AES key is per-candidate** — the schedule is inside the hot loop; it is the main cost, not MD5.
- **Only ~2.3% of candidates survive `first_byte`** — keep divergent structural checks after it.
- **Port all four wallet branches** (`K/L/Q/5`, `\n`, `#`) to avoid missing valid hits; the base58 branch
  is the common MultiBit Classic case.
- **KnC/bitcoinj literal compares in the kernel are byte-swapped `u32`s** — in a native LE port compare the
  plain ASCII words.
- **Watchdog / TDR:** on Windows a kernel running > ~2 s can be killed by the driver TDR. Chunk launches
  (§2.2) so each is sub-second, or raise/disable TDR for headless mining rigs.
- **`sm_120` needs CUDA ≥ 12.8** — an older toolkit silently mis-targets or falls back to PTX JIT.

---

## Appendix — mapping hashcat symbols → your port

| hashcat (OpenCL) | your CUDA port |
|---|---|
| `pws[gid].i[]`, `pw_len` | on-device `index_to_password()` output |
| `words_buf_r[il]`, `w0l\|w0r` | inner loop over charset position 0 |
| `salt_bufs[].salt_buf[0..1]` | `__constant__ salt[8]` |
| `salt_bufs[].salt_buf[2..9]` | `__constant__ C0[16], C1[16]` |
| `md5_ctx_t` + `MD5_STEP`/`Fo/Go/H/I` | `md5.cuh` (single-block, pre-add hoist) |
| `aes256_set_decrypt_key`, `aes256_decrypt`, `te*/td*` | `aes.cuh` (T-tables in shared) |
| `is_valid_base58_32/_8`, `is_valid_bitcoinj_8` | `verify.hpp` predicates |
| `mark_hash` + `hashes_shown` atomic | `__device__ Result` + `atomicCAS` |
| `KERN_ATTR_VECTOR`, `VECT_SIZE` | drop; use TLP, `VECT_SIZE = 1` |
```
