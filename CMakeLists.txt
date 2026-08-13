cmake_minimum_required(VERSION 3.24)

# GPU backend is opt-in so the CPU tool builds anywhere (incl. before CUDA is installed).
option(USE_CUDA "Build the CUDA (RTX 5090) backend" OFF)

if(USE_CUDA)
    project(mbcrack LANGUAGES CXX CUDA)
else()
    project(mbcrack LANGUAGES CXX)
endif()

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ---- main cracker ----
if(USE_CUDA)
    set(CMAKE_CUDA_STANDARD 17)
    set(CMAKE_CUDA_ARCHITECTURES 120)          # RTX 5090 = sm_120  (requires CUDA >= 12.8)
    set(MB_MINBLOCKS 2 CACHE STRING "__launch_bounds__ minBlocksPerMP (1|2|3); occupancy/spill knob")
    add_executable(mbcrack src/main.cpp src/kernel.cu)
    target_compile_definitions(mbcrack PRIVATE USE_CUDA MB_MINBLOCKS=${MB_MINBLOCKS})
    target_compile_options(mbcrack PRIVATE
        $<$<COMPILE_LANGUAGE:CUDA>:--ptxas-options=-v -lineinfo>)
else()
    add_executable(mbcrack src/main.cpp)
    find_package(Threads REQUIRED)
    target_link_libraries(mbcrack PRIVATE Threads::Threads)
endif()
target_include_directories(mbcrack PRIVATE src)

# ---- CPU self-test (always CPU, buildable with g++/MSVC, no CUDA) ----
add_executable(selftest test/selftest.cpp)
target_include_directories(selftest PRIVATE src)

# ---- synthetic test-vector generator (CPU) ----
add_executable(gen_vector tools/gen_vector.cpp)
target_include_directories(gen_vector PRIVATE src)

enable_testing()
add_test(NAME selftest COMMAND selftest)
add_test(NAME gen_vector_selftest COMMAND gen_vector --selftest)
