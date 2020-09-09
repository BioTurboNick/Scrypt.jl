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
 - Further vectorized, removed some abstraction. Weirdly, vectorization of the prepare/restore functions made it marginally slower, although no difference in allocations, did not keep: 261.690 ms (1311110 allocations: 196.05 MiB)
 - Implemented memory-aligned and nontemporal load/store methods for fill/mix functions: 150.639 ms (524678 allocations: 88.07 MiB) (commit 857cd7a92a797bd67ca22d684e051432d6f7e48d)
 - Got rid of an internal array I had introduced in the inner loop accidentally: 85.645 ms (390 allocations: 16.07 MiB) (commit 6a48816057494a1770c9406723440216da68df97)
 - Implemented nontemporal store instructions, increased time a bit, but more secure: 90.233 ms (390 allocations: 16.07 MiB)
 - Added @inbounds to load/store methods: 88.039 ms (70 allocations: 16.03 MiB)

 16 MiB is about the lower limit of allocation amount for the parameters I was using.


 End result: Only ~2 times slower than my original C++/C# package, after starting ~525 times slower. A bit more optimization to try to squeeze out.
