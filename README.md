# Scrypt.jl

[![ci](https://github.com/BioTurboNick/Scrypt.jl/actions/workflows/main.yml/badge.svg)](https://github.com/BioTurboNick/Scrypt.jl/actions/workflows/main.yml)
[![codecov.io](https://codecov.io/github/BioTurboNick/Scrypt.jl/coverage.svg?branch=master)](https://codecov.io/github/BioTurboNick/Scrypt.jl?branch=master)

Port of my [Skryptonite](https://github.com/BioTurboNick/Skryptonite) C++/C# implementation of the Scrypt password-bassed key derivation algorithm / hash function, in pure Julia.

I make no guarantees other than that it passes the test vectors from the original paper. Contributions welcome.

Skryptonite code is more fully documented, if you wish to understand the logic. But in brief, the data is rearranged for optimal internal operations by placing the last block first and organizing the internal matrix blocks so that the diagonals are moved into columns.

Example:
```
r = 8
N = 16384
p = 1
key = Vector{UInt8}(b"pleaseletmein")
salt = Vector{UInt8}(b"SodiumChloride")
derivedkeylength = 64 # bytes
scrypt(ScryptParameters(r, N, p), key, salt, derivedkeylength)
scrypt(ScryptParameters(r, N, p), key, salt, derivedkeylength; ntasks = 1) # use single thread instead of default Threads.nthreads() threads.
```

Optimization notes:
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
 - Added @inbounds to load/store methods: 79.289 ms (390 allocations: 16.07 MiB); v0.2.1
 - New computer at this point, so timings don't exactly match: 66.476 ms (11276 allocations: 20.94 MiB); I suspect the change from Array to Memory inside Julia is partly responsible for this.
 - Switched away from  `permute!`/`invpermute!` in favor of `getindex`/`setindex`, as documentation advises, to avoid their internal allocations
 - Revised `pbkdf2_sha256_1` to avoid repeated allocations of the HMAC state from inside Nettle.
 - Switched from SIMD.jl operations to broadcasted Tuple operations in inner loop (macro expansion for `@simd` seems to be heavy): 55.997 ms (742 allocations: 16.07 MiB); this change more greatly impacted performance of higher `p` parameter as well by allowing buffer reuse between iterations.

 16 MiB is about the lower limit of allocation amount for the parameters I was using.

 End result: About matches performance of my original C++/C# package, after starting ~525 times slower.



