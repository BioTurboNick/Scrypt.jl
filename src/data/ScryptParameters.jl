maxuint = 2^32 - 1

struct ScryptParameters
    r::UInt  # element length multiplier
    N::UInt  # processing cost
    p::UInt  # parallelization

    function ScryptParameters(r, N, p)
        r > 0 || ArgumentError("r Must be > 0.") |> throw
        N > 0 || ArgumentError("N Must be > 0.") |> throw
        p > 0 || ArgumentError("p Must be > 0.") |> throw

        parameters = new(UInt(r), UInt(N), UInt(p))

        p ≤ maxuint * hashlength(parameters) / elementlength(parameters) || 
            ArgumentError("p and r must satisfy the relationship p ≤ (2^32 - 1) * hashlength / elementlength)") |> throw

        r * N * elementunitlength(parameters) ≤ Sys.total_memory() ||
            ArgumentError("r and N must satisfy the relationship r * N * elementunitlength ≤ Sys.total_memory") |> throw

        parameters
    end
end


bytes(x) = x ÷ 8

hashbitslength(::ScryptParameters) = 256
hashlength(x::ScryptParameters) = hashbitslength(x) |> bytes

elementunitbitslength(::ScryptParameters) = 1024
elementunitlength(x::ScryptParameters) = elementunitbitslength(x) |> bytes
elementlength(x::ScryptParameters) = elementunitlength(x) * x.r
bufferlength(x::ScryptParameters) = elementlength(x) * x.p
elementblockcount(x::ScryptParameters) = elementlength(x) ÷ sizeof(SalsaBlock)
