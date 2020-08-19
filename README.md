# Scrypt.jl

[![Build Status](https://travis-ci.com/BioTurboNick/Scrypt.jl.svg?branch=master)](https://travis-ci.com/github/BioTurboNick/Scrypt.jl)
[![codecov.io](https://codecov.io/github/BioTurboNick/Scrypt.jl/coverage.svg?branch=master)](https://codecov.io/github/BioTurboNick/Scrypt.jl?branch=master)

Port of my [Skryptonite](https://github.com/BioTurboNick/Skryptonite) C++/C# implementation of the Scrypt password-bassed key derivation algorithm / hash function, in pure Julia.

I make no guarantees other than that it passes the test vectors from the original paper. Contributions welcome.

Skryptonite code is more fully documented, if you wish to understand the logic. But in brief, the data is rearranged for optimal internal operations by placing the last block first and organizing the internal matrix blocks so that the diagonals are moved into columns.

One thing this lacks right now is parallelization for the p parameter.



Optimization path:
 - Initial: 7.511 s (93602212 allocations: 8.63 GiB) (commit )
 - Moved constant array selectors into global constants: 7.206 s (81019300 allocations: 7.32 GiB) (commit )
 - Just prior to the critical inner loop, copied the data to an MMatrix from StaticArrays: 1.455 s (81019300 allocations: 3.29 GiB) (commit )
 - Refactored and simplified: 1.642 s (81281446 allocations: 3.27 GiB) (commit )
 - Changed salsamix!() function to loop over rows instead of over columns, paradoxically: 1.130 s (17234346 allocations: 1.48 GiB) (commit )
