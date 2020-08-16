# Scrypt.jl

[![Build Status](https://travis-ci.org/BioTurboNick/Scrypt.jl.svg?branch=master)](https://travis-ci.org/BioTurboNick/Scrypt.jl)
[![codecov.io](https://codecov.io/github/BioTurboNick/Scrypt.jl/coverage.svg?branch=master)](https://codecov.io/github/BioTurboNick/Scrypt.jl?branch=master)

Port of my Skryptonite C++/C# implementation of the Scrypt password-bassed key derivation algorithm / hash function.

I make no guarantees other than that it passes the test vectors from the original paper. This implementation is ~16x slower than my native implemenation, because it has not been fully optimized for Julia. I may not attempt to optimize myself, as I have no direct use for this code. Contributions welcome.

Skryptonite code is more fully documented, if you wish to understand the logic. But in brief, the data is rearranged for optimal internal operations by placing the last block first and organizing the internal matrix blocks so that the diagonals are moved into columns.