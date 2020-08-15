maxuint = 2^32 - 1

struct ScryptParameters
    r::UInt  # element length multiplier
    N::UInt  # processing cost
    p::UInt  # parallelization

    function ScryptParameters(r::UInt, N::UInt, p::UInt)
        r > 0 || ArgumentError("r Must be > 0.") |> throw
        N > 0 || ArgumentError("N Must be > 0.") |> throw
        p > 0 || ArgumentError("p Must be > 0.") |> throw

        parameters = new(r, N, p)

        p ≤ maxuint * hashlength(scrypt) / (r * elementunitlength(scrypt)) || 
            ArgumentError("p and r must satisfy the relationship p ≤ (2^32 - 1) * hashlength / (r * elementunitlength)") |> throw

        r * N * bytes(elementunitlength(scrypt)) ≤ Sys.total_memory() ||
            ArgumentError("r and N must satisfy the relationship r * N * elementunitlength / 8 ≤ Sys.total_memory") |> throw

        parameters
    end
end


bytes(x) = x ÷ 8

hashlength(::ScryptParameters) = 256

elementunitlength(::ScryptParameters) = 1024

elementlength(x::ScryptParameters) = elementunitlength * x.r

elementblockcount(x::ScryptParameters) = elementlength(x) ÷ (8 * sizeof(SalsaBlock))

workingbufferlength(x::ScryptParameters) = bytes(elementunitlength(x)) * x.r * x.p
