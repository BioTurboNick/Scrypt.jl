
"""
    ScryptParameters(r::Int, N::Int, p::Int)

A struct to hold Scrypt parameters.

# Parameters

- `r::Int`: Block size factor. Affects how much memory is used per "chunk" of work. Must be > 0.
- `N::Int`: CPU/Memory cost factor. The biggest number — controls how much memory and time the function uses. Higher N = more secure, but also slower and uses more memory. Must be a power of 2, > 1.
- `p::Int`: Parallelization factor. How many independent tasks can run at the same time. Higher p = uses more CPU cores, but also multiplies the total memory. Must be > 0.

Note: In Scrypt.jl, if you use single-threaded `scrypt` with `p>1`, memory buffer will be reused, so the peak memory is roughly `1/p` of parallel version `scrypt_threaded`.
"""
struct ScryptParameters
    r::Int  # element length multiplier
    N::Int  # processing cost
    p::Int  # parallelization

    function ScryptParameters(r, N, p)
        r > 0 || throw(ArgumentError("r Must be > 0."))
        N > 0 || throw(ArgumentError("N Must be > 0."))
        p > 0 || throw(ArgumentError("p Must be > 0."))

        parameters = new(UInt(r), UInt(N), UInt(p))

        # (2^32 - 1) = 4294967295
        p ≤ 4294967295 * hashlength(parameters) / elementlength(parameters) || 
            throw(ArgumentError("p and r must satisfy the relationship p ≤ (2^32 - 1) * hashlength / elementlength)"))

        r * N * elementunitlength(parameters) ≤ Sys.total_memory() ||
            throw(ArgumentError("r and N must satisfy the relationship r * N * elementunitlength ≤ Sys.total_memory"))

        parameters
    end
end

@inline hashbitslength(::ScryptParameters) = 256
@inline hashlength(x::ScryptParameters) = hashbitslength(x) ÷ 8

@eval @inline elementunitbitslength(::ScryptParameters) = $(2 * 8 * 64)
@inline elementunitlength(x::ScryptParameters) = elementunitbitslength(x) ÷ 8
@inline elementlength(x::ScryptParameters) = elementunitlength(x) * x.r
@inline bufferlength(x::ScryptParameters) = elementlength(x) * x.p
@inline elementblockcount(x::ScryptParameters) = elementlength(x) ÷ 64
