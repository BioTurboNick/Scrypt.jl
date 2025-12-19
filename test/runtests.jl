using Scrypt
using Test

@testset "Scrypt Tests" begin
    expected = [hex2bytes("77d6576238657b203b19ca42c18a0497f16b4844e3074ae8dfdffa3fede21442fcd0069ded0948f8326a753a0fc81f17e8d3e0fb2e0d3628cf35e20c38d18906"),
                hex2bytes("b034a96734ebdc650fca132f40ffde0823c2f780d675eb81c85ec337d3b1176017061beeb3ba18df59802b95a325f5f850b6fd9efb1a6314f835057c90702b19"),
                hex2bytes("fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b3731622eaf30d92e22a3886ff109279d9830dac727afb94a83ee6d8360cbdfa2cc0640"),
                hex2bytes("7023bdcb3afd7348461c06cd81fd38ebfda8fbba904f8e3ea9b543f6545da1f2d5432955613f0fcf62d49705242a9af9e61e85dc0d651e40dfcf017b45575887"),
                hex2bytes("2101cb9b6a511aaeaddbbe09cf70f881ec568d574a2ffd4dabe5ee9820adaa478e56fd8f4ba5d09ffa1c6d927c40f4c337304049e8a952fbcbf45c6fa77a41a4")]

    output = [scrypt(ScryptParameters(1, 16, 1), Vector{UInt8}(b""), Vector{UInt8}(b""), 64),
              scrypt(ScryptParameters(2, 32, 2), Vector{UInt8}(b"password"), Vector{UInt8}(b"NaCl"), 64),
              scrypt(ScryptParameters(8, 1024, 16), Vector{UInt8}(b"password"), Vector{UInt8}(b"NaCl"), 64),
              scrypt(ScryptParameters(8, 16384, 1), Vector{UInt8}(b"pleaseletmein"), Vector{UInt8}(b"SodiumChloride"), 64),
              scrypt(ScryptParameters(8, 1048576, 1), Vector{UInt8}(b"pleaseletmein"), Vector{UInt8}(b"SodiumChloride"), 64)]

    @test all(expected .== output)

    SCRYPT_PARAMS = ScryptParameters(8, 1024, 16)
    for i in 1:100
        key = rand(UInt8, rand(1:128))
        salt = rand(UInt8, rand(0:64))
        dklen = rand(16:128)

        old = Scrypt.scrypt_0(SCRYPT_PARAMS, key, salt, dklen)
        new = Scrypt.scrypt(SCRYPT_PARAMS, key, salt, dklen)

        @test length(old) == length(new)
        @test old == new
    end
end

using Revise, Nettle, Scrypt, Nettle_jll, BenchmarkTools, Test, SIMD, LoopVectorization
Salsa512 = Scrypt.Salsa512

##### common
HASH_LENGTH = 256 ÷ 8
parameters = ScryptParameters(8, 1024, 16)
key = Vector{UInt8}(b"password")
salt = UInt8[]
derivedkeylength = Scrypt.bufferlength(parameters)
buf_len = derivedkeylength

# check same as old scrypt
Scrypt.scrypt(ScryptParameters(8, 1024, 16), Vector{UInt8}(b"password"), Vector{UInt8}(b"NaCl"), 64) == Scrypt.scrypt_0(ScryptParameters(8, 1024, 16), Vector{UInt8}(b"password"), Vector{UInt8}(b"NaCl"), 64)

# speed test
@time Scrypt.scrypt(ScryptParameters(8, 1024, 16), Vector{UInt8}(b"password"), Vector{UInt8}(b"NaCl"), 64);
@profview Scrypt.scrypt(ScryptParameters(8, 1024, 16), Vector{UInt8}(b"password"), Vector{UInt8}(b"NaCl"), 64)
@BenchmarkTools.benchmark Scrypt.scrypt(ScryptParameters(8, 1024, 16), Vector{UInt8}(b"password"), Vector{UInt8}(b"NaCl"), 64)
# Range (min … max):  71.562 ms … 89.970 ms  ┊ GC (min … max): 0.00% … 0.00%
#  Time  (median):     72.522 ms              ┊ GC (median):    0.00%
#  Time  (mean ± σ):   73.563 ms ±  2.822 ms  ┊ GC (mean ± σ):  0.00% ± 0.00%

#     ▆█▆█▁ ▁                                                    
#   ▄▄█████▇█▁▇▁▁▆▇▄▆▆▆▄▄▁▄▁▁▁▁▁▁▁▁▁▁▁▁▄▁▁▁▁▁▁▁▁▁▁▁▄▁▁▁▄▄▄▁▁▁▁▄ ▁
#   71.6 ms         Histogram: frequency by time        80.3 ms <

#  Memory estimate: 1.08 MiB, allocs estimate: 149.

# compare buffer diff
buffer = Scrypt.pbkdf2_sha256_1(key, salt, Scrypt.bufferlength(parameters))

i=1
j=2
r = parameters.r
N = parameters.N

### old
buffer = Scrypt.pbkdf2_sha256_1(key, salt, Scrypt.bufferlength(parameters))

parallelbuffer = reshape(reinterpret(Salsa512, buffer), (Scrypt.elementblockcount(parameters), parameters.p))

element = reshape(@view(parallelbuffer[:, i]), Scrypt.elementblockcount(parameters))

#    smix
workingbuffer = Scrypt.prepare(element)
shufflebuffer = valloc(Salsa512, length(workingbuffer))

#    fillscryptblock!
scryptblock = reshape(valloc(Salsa512, 2r * N), (2r, N))
#        for i ∈ 1:N
scryptelement = view(scryptblock, :, i)
previousblock = lastblock = Scrypt.load_store!(workingbuffer, scryptelement, 1)
#             for j ∈ 2:2r
block = Scrypt.load_store!(workingbuffer, scryptelement, j)
block = Scrypt.mixblock_shuffle_store!(block, previousblock, shufflebuffer, Scrypt.shuffleposition(j, r))

### new
buffer2 = Scrypt.pbkdf2_sha256_1(key, salt, Scrypt.bufferlength(parameters))

parallelbuffer_2 = unsafe_wrap(Array{UInt32,3}, Ptr{UInt32}(pointer(buffer2)), (16, Scrypt.elementblockcount(parameters), parameters.p));
workingbuffer_new = Matrix{UInt32}(undef, (16, Scrypt.elementblockcount(parameters)))
    shufflebuffer_new = Matrix{UInt32}(undef, (16, Scrypt.elementblockcount(parameters)))
    scryptblock_new = Array{UInt32,3}(undef, 16, 2*parameters.r, parameters.N);

element_new = reshape(@view(parallelbuffer_2[:, :, i]), (16, Scrypt.elementblockcount(parameters)))

#    smix_new
Scrypt.prepare_new!(workingbuffer_new, element_new)

#    fillscryptblock_new!: ok
previousblock_new = Vector{UInt32}(undef, 16);
block_new = Vector{UInt32}(undef, 16);
#        for i ∈ 1:N
scryptelement_new = view(scryptblock_new, :, :, i)
last_block_new = @view workingbuffer_new[:, 1]
scryptelement_new[:, 1] .= last_block_new
previousblock_new .= last_block_new
#             for j ∈ 2:2r
block_new .= @view workingbuffer_new[:, j] #ok
scryptelement_new[:, j] .= block_new
Scrypt.mixblock_shuffle_store_new!(block_new, previousblock_new, shufflebuffer_new, Scrypt.shuffleposition(j, r))

# check diff:
scryptblock_new[:,:, 1]
scryptblock[:, 1]

shufflebuffer_new[:,j]
shufflebuffer[j]

block_new
block

workingbuffer_new
workingbuffer

##### after check ok:
### new
for j ∈ 2+1:2r
    # block = load_store!(workingbuffer, scryptelement, j)
    block_new .= @view workingbuffer_new[:, j] #ok
    scryptelement_new[:, j] .= block_new

    Scrypt.mixblock_shuffle_store_new!(block_new, previousblock_new, shufflebuffer_new, Scrypt.shuffleposition(j, r))
    # block_new, shufflebuffer_new NOT OK
    # previousblock_new, workingbuffer_new ok
    previousblock_new .= block_new #TODO might be error here?
end
block_new .= @view workingbuffer_new[:, 1]
Scrypt.mixblock_shuffle_store_new!(block_new, previousblock_new, shufflebuffer_new, 1)
### old
for j ∈ 2+1:2r
    block = Scrypt.load_store!(workingbuffer, scryptelement, j)
    block = Scrypt.mixblock_shuffle_store!(block, previousblock, shufflebuffer, Scrypt.shuffleposition(j, r))
    previousblock = block
end
Scrypt.mixblock_shuffle_store!(lastblock, previousblock, shufflebuffer, 1)
### check ok: fillscryptblock_new!







########## REDO, fillscryptblock_new! is safe:
### old
buffer = Scrypt.pbkdf2_sha256_1(key, salt, Scrypt.bufferlength(parameters))

parallelbuffer = reshape(reinterpret(Salsa512, buffer), (Scrypt.elementblockcount(parameters), parameters.p))

element = reshape(@view(parallelbuffer[:, i]), Scrypt.elementblockcount(parameters))

#    smix
workingbuffer = Scrypt.prepare(element)
shufflebuffer = valloc(Salsa512, length(workingbuffer))
scryptblock, workingbuffer, shufflebuffer = Scrypt.fillscryptblock!(workingbuffer, shufflebuffer, parameters.r, parameters.N)

### new
buffer2 = Scrypt.pbkdf2_sha256_1(key, salt, Scrypt.bufferlength(parameters))

parallelbuffer_2 = unsafe_wrap(Array{UInt32,3}, Ptr{UInt32}(pointer(buffer2)), (16, Scrypt.elementblockcount(parameters), parameters.p));
workingbuffer_new = Matrix{UInt32}(undef, (16, Scrypt.elementblockcount(parameters)))
    shufflebuffer_new = Matrix{UInt32}(undef, (16, Scrypt.elementblockcount(parameters)))
    scryptblock_new = Array{UInt32,3}(undef, 16, 2*parameters.r, parameters.N);

element_new = reshape(@view(parallelbuffer_2[:, :, i]), (16, Scrypt.elementblockcount(parameters)))

#    smix_new
Scrypt.prepare_new!(workingbuffer_new, element_new)
scryptblock_new, workingbuffer_new, shufflebuffer_new = Scrypt.fillscryptblock_new!(scryptblock_new, workingbuffer_new, shufflebuffer_new, parameters.r, parameters.N)

# NOW CHECK: mixwithscryptblock!

### old
n = Scrypt.integerify(workingbuffer, N)
scryptelement = reshape(view(scryptblock, :, n), 2r)

scryptelement_0 = deepcopy(scryptelement[:])

@time previousblock = lastblock = Scrypt.load_xor(workingbuffer, scryptelement, 1)

### new
n = Scrypt.integerify(workingbuffer_new, N)
scryptelement_new = view(scryptblock_new, :, :, n)
scryptelement_0 = deepcopy(scryptelement_new[:, :])

previousblock_new = Vector{UInt32}(undef, 16);
lastblock_new = Vector{UInt32}(undef, 16);
block_new = Vector{UInt32}(undef, 16);

@inbounds for m in 1:16  # load_xor
    previousblock_new[m] = lastblock_new[m] = workingbuffer_new[m, 1] ⊻ scryptelement_new[m, 1]
end

@inbounds for m in 1:16
    block_new[m] = workingbuffer_new[m, j] ⊻ scryptelement_new[m, j]
end