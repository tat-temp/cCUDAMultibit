// cuda_stub.h — compile the CUDA device headers on the host (g++) for correctness testing.
// Maps nvcc-only execution-space qualifiers to no-ops when __CUDACC__ is not defined, so the
// EXACT device per-candidate pipeline (pipeline.cuh: dev_try_password / dev_finish_from_key1)
// can be run against the CPU reference (pipeline_ref.h) in the self-test, with no GPU. Under
// nvcc (__CUDACC__ defined) this header is inert and the real qualifiers apply.
#pragma once
#ifndef __CUDACC__
  #ifndef __device__
  #define __device__
  #endif
  #ifndef __host__
  #define __host__
  #endif
  #ifndef __global__
  #define __global__
  #endif
  #ifndef __constant__
  #define __constant__
  #endif
  #ifndef __shared__
  #define __shared__
  #endif
  #ifndef __forceinline__
  #define __forceinline__ inline
  #endif
#endif
