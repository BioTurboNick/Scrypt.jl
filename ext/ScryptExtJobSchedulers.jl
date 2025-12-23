module ScryptExtJobSchedulers

using JobSchedulers
using Scrypt

"""
    scrypt_threaded(parameters::ScryptParameters, key::Vector{UInt8}, derivedkeylength::Integer, job_priority::Int)
    scrypt_threaded(parameters::ScryptParameters, key::Vector{UInt8}, salt::Vector{UInt8}, derivedkeylength::Integer, job_priority::Int)

Return a derived key of length `derivedkeylength` bytes, derived from the given `key` and optional `salt`, using the scrypt key derivation function with the specified `parameters`.

- `job_priority::Int`: The priority of the jobs created for parallel execution. Lower values indicate higher priority. The default priority of regular jobs is `20`.

It uses `JobSchedulers.jl` to parallelize the computation if `parameters.p > 1`. To use `Base.Threads` for parallelization, please use the `scrypt_threaded` function without the `job_priority` argument.
"""
function Scrypt.scrypt_threaded(parameters::ScryptParameters, key::Vector{UInt8}, salt::Vector{UInt8}, derivedkeylength::Integer, job_priority::Int)

    derivedkeylength > 0 || throw(ArgumentError("Must be > 0."))

    buffer = Scrypt.pbkdf2_sha256_1(key, salt, Scrypt.bufferlength(parameters))
    parallelbuffer = unsafe_wrap(Array{UInt32,3}, Ptr{UInt32}(pointer(buffer)), (16, Scrypt.elementblockcount(parameters), parameters.p));

    jobs = Job[]
    for i ∈ 1:parameters.p
        job = Job(; priority = job_priority) do 
            workingbuffer = Matrix{UInt32}(undef, (16, Scrypt.elementblockcount(parameters)))
            shufflebuffer = Matrix{UInt32}(undef, (16, Scrypt.elementblockcount(parameters)))
            scryptblock = Array{UInt32,3}(undef, 16, 2*parameters.r, parameters.N);

            element = @view(parallelbuffer[:, :, i])
            Scrypt.smix!(scryptblock, workingbuffer, shufflebuffer, element, parameters)
        end
        submit!(job)
        push!(jobs, job)
    end

    for j in jobs
        wait(j)
    end

    derivedkey = Scrypt.pbkdf2_sha256_1(key, buffer, derivedkeylength)
end 

function Scrypt.scrypt_threaded(parameters::ScryptParameters, key::Vector{UInt8}, derivedkeylength::Integer, job_priority::Int)
    scrypt_threaded(parameters, key, Scrypt.EMPTY_SALT, derivedkeylength, job_priority)
end

end