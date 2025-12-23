@setup_workload begin
    # Putting some things in `@setup_workload` instead of `@compile_workload` can reduce the size of the
    # precompile file and potentially make loading faster.
    @compile_workload begin
        # all calls in this block will be precompiled, regardless of whether
        # they belong to your package or not (on Julia 1.8 and higher)
        scrypt(ScryptParameters(1, 16, 1), Vector{UInt8}(b""), 64)
        scrypt(ScryptParameters(2, 32, 2), Vector{UInt8}(b"password"), Vector{UInt8}(b"NaCl"), 64)
        scrypt_threaded(ScryptParameters(1, 16, 1), Vector{UInt8}(b""), 64)
        scrypt_threaded(ScryptParameters(2, 32, 2), Vector{UInt8}(b"password"), Vector{UInt8}(b"NaCl"), 64)
    end
end
