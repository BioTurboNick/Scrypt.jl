# Scrypt.jl

[![Build Status](https://travis-ci.com/BioTurboNick/Scrypt.jl.svg?branch=master)](https://travis-ci.com/github/BioTurboNick/Scrypt.jl)
[![codecov.io](https://codecov.io/github/BioTurboNick/Scrypt.jl/coverage.svg?branch=master)](https://codecov.io/github/BioTurboNick/Scrypt.jl?branch=master)

Scrypt is a password-based key derivation function (KDF) designed to be **memory-hard** and **computationally expensive**, making it significantly more resistant to brute-force attacks and hardware-accelerated cracking (especially GPU/ASIC attacks) compared to earlier functions like PBKDF2, bcrypt, or SHA-256.

Port of my [Skryptonite](https://github.com/BioTurboNick/Skryptonite) C++/C# implementation of the Scrypt password-bassed key derivation algorithm / hash function, in pure Julia. Rewrite (v0.2.2) by @cihga39871 to achieve better performance.

I make no guarantees other than that it passes the test vectors from the original paper. Contributions welcome.

Skryptonite code is more fully documented, if you wish to understand the logic. But in brief, the data is rearranged for optimal internal operations by placing the last block first and organizing the internal matrix blocks so that the diagonals are moved into columns.

## Quick Start

```julia
using Scrypt

r = 8
N = 16384
p = 1
key = Vector{UInt8}(b"pleaseletmein")
salt = Vector{UInt8}(b"SodiumChloride")
derivedkeylength = 64 # length of the returned derived key

scrypt(ScryptParameters(r, N, p), key, salt, derivedkeylength)
# 64-element Vector{UInt8}:
#  0x70
#  0x23
#  0xbd
#     ⋮
#  0x58
#  0x87
```

## API

### `ScryptParameters`

```julia
ScryptParameters(r::Int, N::Int, p::Int)
```

A struct to hold Scrypt parameters.

Parameters:

- `r::Int`: Block size factor. Affects how much memory is used per "chunk" of work. Must be > 0.
- `N::Int`: CPU/Memory cost factor. The biggest number — controls how much memory and time the function uses. Higher N = more secure, but also slower and uses more memory. Must be a power of 2, > 1.
- `p::Int`: Parallelization factor. How many independent tasks can run at the same time. Higher p = uses more CPU cores, but also multiplies the total memory. Must be > 0.

Note: In Scrypt.jl, if you use single-threaded `scrypt` with `p>1`, memory buffer will be reused, so the peak memory is roughly `1/p` of its parallel version `scrypt_threaded`.

### `scrypt`

```julia
scrypt(parameters::ScryptParameters, key::Vector{UInt8}, derivedkeylength::Integer)
scrypt(parameters::ScryptParameters, key::Vector{UInt8}, salt::Vector{UInt8}, derivedkeylength::Integer)
```

Return a derived key of length `derivedkeylength` bytes, derived from the given `key` and optional `salt`, using the scrypt key derivation function with the specified `parameters`.

### `scrypt_threaded` (parallel using Base.Threads)

```julia
scrypt_threaded(parameters::ScryptParameters, key::Vector{UInt8}, derivedkeylength::Integer)
scrypt_threaded(parameters::ScryptParameters, key::Vector{UInt8}, salt::Vector{UInt8}, derivedkeylength::Integer)
```

It uses `Base.Threads` to parallelize the computation if `parameters.p > 1`.

### `scrypt_threaded` (parallel using JobSchedulers package)

> **Compat:** The following methods are only available for Julia version >=v1.9.0 and when you `using JobSchedulers`.

```julia
scrypt_threaded(parameters::ScryptParameters, key::Vector{UInt8}, derivedkeylength::Integer, job_priority::Int)
scrypt_threaded(parameters::ScryptParameters, key::Vector{UInt8}, salt::Vector{UInt8}, derivedkeylength::Integer, job_priority::Int)
```

- `job_priority::Int`: The priority of the jobs created for parallel execution. Lower values indicate higher priority. The default priority of regular jobs is `20`.

It uses `JobSchedulers.jl` to parallelize the computation if `parameters.p > 1`. To use `Base.Threads` for parallelization, please use the `scrypt_threaded` function without the `job_priority` argument.

## Optimization notes

 - Initial: 7.511 s (93602212 allocations: 8.63 GiB) (commit 79ccff573b132d9079f908b02a717b58fa71a710)
 - Moved constant array selectors into global constants: 7.206 s (81019300 allocations: 7.32 GiB) (commit 9195adc4a87f06068ba6b3e7da23188cf9c22c67)
 - Just prior to the critical inner loop, copied the data to an MMatrix from StaticArrays: 1.455 s (81019300 allocations: 3.29 GiB) (commit 4b716febb788ff2b1493eb03e63e9034565b48e8)
 - Refactored and simplified: 1.642 s (81281446 allocations: 3.27 GiB) (commit 98cdaee685836c636f1abdf6745d6260de219a79)
 - Changed salsamix!() function to loop over rows instead of over columns, paradoxically: 1.130 s (17234346 allocations: 1.48 GiB) (commit 94e620944ca398af78eac778ea55580d81972343)
 - Fully implemented SIMD for Salsa20/8 instead of StaticArrays: 312.388 ms (4651434 allocations: 471.02 MiB) (commit c08f960f82f043e0443b73307542ba30ecd97d0b)
 - Cut down a few allocations by using `@code_warntype` to tighten up function types, but minimal improvment overall.
 - Further vectorized, removed some abstraction. Weirdly, vectorization of the prepare/restore functions made it marginally slower, although no difference in allocations, did not keep: 261.690 ms (1311110 allocations: 196.05 MiB)
 - Implemented memory-aligned and nontemporal load/store methods for fill/mix functions: 150.639 ms (524678 allocations: 88.07 MiB) (commit 857cd7a92a797bd67ca22d684e051432d6f7e48d)
 - Got rid of an internal array I had introduced in the inner loop accidentally: 85.645 ms (390 allocations: 16.07 MiB) (commit 6a48816057494a1770c9406723440216da68df97)
 - Implemented nontemporal store instructions, increased time a bit, but more secure: 90.233 ms (390 allocations: 16.07 MiB)
 - Added @inbounds to load/store methods: 79.289 ms (390 allocations: 16.07 MiB)

 16 MiB is about the lower limit of allocation amount for the parameters I was using.

 Rresult: Only ~2 times slower than my original C++/C# package, after starting ~525 times slower. A bit more optimization to try to squeeze out.

 - v0.2.2: main implementation rewrite: julia native structs and simd, reuse arrays, avoid array operations, and inline most of functions. 2~2.5X Faster than v0.2.1.