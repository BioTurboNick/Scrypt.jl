# Scrypt.jl

[![Build Status](https://travis-ci.com/BioTurboNick/Scrypt.jl.svg?branch=master)](https://travis-ci.com/github/BioTurboNick/Scrypt.jl)
[![codecov.io](https://codecov.io/github/BioTurboNick/Scrypt.jl/coverage.svg?branch=master)](https://codecov.io/github/BioTurboNick/Scrypt.jl?branch=master)

Port of my [Skryptonite](https://github.com/BioTurboNick/Skryptonite) C++/C# implementation of the Scrypt password-bassed key derivation algorithm / hash function, in pure Julia.

I make no guarantees other than that it passes the test vectors from the original paper. Contributions welcome.

Skryptonite code is more fully documented, if you wish to understand the logic. But in brief, the data is rearranged for optimal internal operations by placing the last block first and organizing the internal matrix blocks so that the diagonals are moved into columns.

One thing this lacks right now is parallelization for the p parameter.



Optimization notes:
 - Initial: 7.511 s (93602212 allocations: 8.63 GiB) (commit 79ccff573b132d9079f908b02a717b58fa71a710)
 - Moved constant array selectors into global constants: 7.206 s (81019300 allocations: 7.32 GiB) (commit 9195adc4a87f06068ba6b3e7da23188cf9c22c67)
 - Just prior to the critical inner loop, copied the data to an MMatrix from StaticArrays: 1.455 s (81019300 allocations: 3.29 GiB) (commit 4b716febb788ff2b1493eb03e63e9034565b48e8)
 - Refactored and simplified: 1.642 s (81281446 allocations: 3.27 GiB) (commit 98cdaee685836c636f1abdf6745d6260de219a79)
 - Changed salsamix!() function to loop over rows instead of over columns, paradoxically: 1.130 s (17234346 allocations: 1.48 GiB) (commit 94e620944ca398af78eac778ea55580d81972343)
 - Fully implemented SIMD for Salsa20/8 instead of StaticArrays: 312.388 ms (4651434 allocations: 471.02 MiB) (commit c08f960f82f043e0443b73307542ba30ecd97d0b)
 - Cut down a few allocations by using `@code_warntype` to tighten up function types, but minimal improvment overall.
 - Further vectorized, removed some abstraction. Weirdly, vectorization of the prepare/restore functions made it marginally slower, although no difference in allocations: 261.690 ms (1311110 allocations: 196.05 MiB)
 - Implemented memory-aligned and nontemporal load/store methods for fill/mix functions: 143.491 ms (524678 allocations: 88.07 MiB)


 End result: Only ~5 times slower than my original C++/C# package, after starting ~525 times slower. A bit more optimization to try to squeeze out.

The original C++ code had some advantages that I don't currently have access to, without a lot more work:
1. Prefetching instructions. While CPUs are pretty good at figuring out when sequential access is happening, the point of this algorithm means you're operating barely into sequential read territory during the `mixwithscryptblock` function. Explicit prefetching thus allows you to tell the CPU to pull the data before you need it, so it doesn't have to wait for the data to arrive from RAM.
2. Streaming store instructions. During the `fillscryptblock` function, pushing the data straight to RAM and avoiding the caches again reduces cache thrashing. There's also a concern about cache timing attacks on an algorithm, and keeping that data out of the cache reduces that possibility.
3. Flush instructions. After using a value in `mixwithscryptblock`, flushing the temporary data out of the cache again reduces cache timing attackks, as in 4. This may marginally reduce performance.
4. Other security considerations: pinning the arrays in the same memory locations and erasing the memory when done.
