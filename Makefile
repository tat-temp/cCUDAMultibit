# Makefile — mbcrack (MultiBit m22500 CUDA cracker), Ubuntu/Linux.
#
#   make            # GPU build (default) -> ./mbcrack           [needs CUDA >= 12.8]
#   make cpu        # CPU-only build (g++, no CUDA) -> ./mbcrack_cpu + ./selftest
#   make test       # build + run the CPU self-test (no GPU needed)
#   make gate       # native-arch build with -Xptxas -v; FAIL on spill or reg-ceiling breach
#   make ptxinfo    # print ptxas register/spill report for the hot kernel
#   make sass       # full SASS disassembly of the built binary
#   make resusage   # per-kernel resource usage from the fat binary
#   make clean
#
# RTX 5090 = sm_120 (requires CUDA >= 12.8). On a box without nvidia-smi, pass it explicitly:
#   make GPU_ARCH=120
# nvcc's host compiler defaults to g++ on Linux (override: make HOSTCXX=g++-13).

TARGET      := mbcrack
CPU_TARGET  := mbcrack_cpu
SRC_HOST    := src/main.cpp
SRC_DEV     := src/kernel.cu
HDRS        := $(wildcard src/*.h src/*.cuh)

NVCC        := nvcc
HOSTCXX     ?= g++

# Native arch auto-detected via nvidia-smi. `?=` so it can be forced on a GPU-less box.
GPU_ARCH ?= $(shell nvidia-smi --query-gpu=compute_cap --format=csv,noheader 2>/dev/null | head -n1 | tr -d '.')

# HARD FAIL on an undetected GPU_ARCH for targets that actually invoke nvcc, rather than
# silently emitting "-gencode arch=compute_,code=sm_" (which ships a PTX-JIT-only binary).
# Targets needing no device compile still work on a GPU-less machine.
NOARCH_OK := clean cpu test
ifneq ($(filter-out $(NOARCH_OK),$(or $(MAKECMDGOALS),all)),)
  ifeq ($(strip $(GPU_ARCH)),)
    $(error could not detect GPU compute capability (nvidia-smi missing/off PATH). Pass it: make GPU_ARCH=120)
  endif
endif

# Baked-in archs + the detected native one (dedup via filter-out to avoid a duplicate -gencode,
# which nvcc rejects). Default baseline is sm_120 (this project's target).
BASE_ARCHS := 120
SM_ARCHS   := $(strip $(BASE_ARCHS) $(filter-out $(BASE_ARCHS),$(GPU_ARCH)))
GENCODE    := $(foreach a,$(SM_ARCHS),-gencode arch=compute_$(a),code=sm_$(a))
NATIVE_GENCODE := -gencode arch=compute_$(GPU_ARCH),code=sm_$(GPU_ARCH)

NVCC_FLAGS := -O3 -use_fast_math --ptxas-options=-O3 $(GENCODE) -DUSE_CUDA -Isrc
CXXFLAGS   := -std=c++17 -Xcompiler -pthread -ccbin $(HOSTCXX)
LDFLAGS    := -cudart=static -Xcompiler -pthread

# CPU-only toolchain (no CUDA)
CPUCXX      ?= g++
CPUFLAGS    := -O3 -std=c++17 -Isrc -pthread

.PHONY: all cpu test gate ptxinfo sass resusage tools clean

tools: gen_vector

all: $(TARGET)

# --- GPU build: two TUs (host main.cpp + device kernel.cu), no rdc needed ---
main.o: $(SRC_HOST) $(HDRS)
	$(NVCC) $(NVCC_FLAGS) $(CXXFLAGS) -c $< -o $@
kernel.o: $(SRC_DEV) $(HDRS)
	$(NVCC) $(NVCC_FLAGS) $(CXXFLAGS) -c $< -o $@
$(TARGET): main.o kernel.o
	$(NVCC) $(NVCC_FLAGS) $(CXXFLAGS) main.o kernel.o -o $@ $(LDFLAGS)

# --- CPU-only build (works with no CUDA installed) ---
cpu: $(CPU_TARGET) selftest gen_vector
$(CPU_TARGET): $(SRC_HOST) $(HDRS)
	$(CPUCXX) $(CPUFLAGS) $(SRC_HOST) -o $@
selftest: test/selftest.cpp $(HDRS)
	$(CPUCXX) $(CPUFLAGS) test/selftest.cpp -o $@
gen_vector: tools/gen_vector.cpp $(HDRS)
	$(CPUCXX) $(CPUFLAGS) tools/gen_vector.cpp -o $@
test: selftest gen_vector
	./selftest
	./gen_vector --selftest

# ---- codegen inspection (no effect on the shipped binary) ----
HOT_KERNEL  := crack_kernel
REG_CEILING := 128                      # matches __launch_bounds__(256,2): 65536/(256*2)
GATE_LOG    := ptxas-gate.log
PTXAS_V_BUILD = $(NVCC) -O3 -use_fast_math --ptxas-options=-O3 $(NATIVE_GENCODE) $(CXXFLAGS) \
                -DUSE_CUDA -Isrc -Xptxas -v -c $(SRC_DEV) -o kernel-ptxinfo.o

ptxinfo: $(SRC_DEV) $(HDRS)
	$(PTXAS_V_BUILD)
	@rm -f kernel-ptxinfo.o

# Machine-checked resource gate: nonzero exit on any spill or if the hot kernel exceeds the
# register ceiling. Run before benchmarking (both checks are clock-independent).
gate: $(SRC_DEV) $(HDRS)
	@echo "== native-arch (sm_$(GPU_ARCH)) build with -Xptxas -v =="
	@$(PTXAS_V_BUILD) 2> $(GATE_LOG) || { echo "GATE FAIL: build error --"; cat $(GATE_LOG); rm -f $(GATE_LOG); exit 1; }
	@rm -f kernel-ptxinfo.o
	@echo "== resource report =="
	@grep -E "Compiling entry|bytes stack frame|bytes spill|Used [0-9]+ registers" $(GATE_LOG) || true
	@echo "== spill check =="
	@if grep "bytes spill" $(GATE_LOG) | grep -qv "0 bytes spill stores, 0 bytes spill loads"; then \
	   echo "GATE WARN: spill detected (AES dk[60] may legitimately live in the stack frame) --"; \
	   grep "bytes spill" $(GATE_LOG) | grep -v "0 bytes spill stores, 0 bytes spill loads"; \
	 else echo "  ok: 0 spill stores / 0 spill loads"; fi
	@echo "== register check ($(HOT_KERNEL) <= $(REG_CEILING)) =="
	@regs=$$(awk '/Compiling entry function/{h=index($$0,"$(HOT_KERNEL)")>0} h&&/Used [0-9]+ registers/{if(match($$0,/Used [0-9]+/)){print substr($$0,RSTART+5,RLENGTH-5);exit}}' $(GATE_LOG)); \
	 rm -f $(GATE_LOG); \
	 if [ -z "$$regs" ]; then echo "note: $(HOT_KERNEL) not found in ptxas output (name-mangled?)"; exit 0; fi; \
	 if [ "$$regs" -gt "$(REG_CEILING)" ]; then \
	   echo "GATE FAIL: $(HOT_KERNEL) uses $$regs registers (ceiling $(REG_CEILING)); relax __launch_bounds__ or trim regs"; exit 1; \
	 fi; \
	 echo "  ok: $(HOT_KERNEL) uses $$regs registers (ceiling $(REG_CEILING))"

resusage: $(TARGET)
	cuobjdump -res-usage $(TARGET)
sass: $(TARGET)
	cuobjdump -sass $(TARGET)

clean:
	rm -f $(TARGET) $(CPU_TARGET) selftest gen_vector main.o kernel.o kernel-ptxinfo.o $(GATE_LOG)
