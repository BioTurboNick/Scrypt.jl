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
        # salt = rand(UInt8, rand(0:64))
        dklen = rand(16:128)

        old = Scrypt.scrypt_0(SCRYPT_PARAMS, key, UInt8[], dklen)
        new = Scrypt.scrypt(SCRYPT_PARAMS, key, dklen)

        @test length(old) == length(new)
        @test old == new
    end
end



#=
#= BASELINE
julia> @benchmark scrypt(SCRYPT_PARAMS, Vector{UInt8}(b"password"), UInt8[], 64)
BenchmarkTools.Trial: 60 samples with 1 evaluation per sample.
 Range (min … max):  81.020 ms … 90.866 ms  ┊ GC (min … max): 0.00% … 0.00%
 Time  (median):     82.050 ms              ┊ GC (median):    0.51%
 Time  (mean ± σ):   83.306 ms ±  2.885 ms  ┊ GC (mean ± σ):  0.78% ± 1.27%

      █▅▁▂                                                     
  ▆▃▆█████▅▁▃▆▁▁▅▁▁▁▁▁▁▁▃▁▁▃▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▃▁▁▁▁▁▁▁▆▆▁▃▁▁▁▃ ▁
  81 ms           Histogram: frequency by time        90.4 ms <

 Memory estimate: 20.90 MiB, allocs estimate: 11278.

=#
HASH_LENGTH = 256 ÷ 8
parameters = ScryptParameters(8, 1024, 16)
key = Vector{UInt8}(b"password")
salt = UInt8[]
derivedkeylength = Scrypt.bufferlength(parameters)

buf_len = derivedkeylength
buffer = Scrypt.pbkdf2_sha256_1(key, buf_len)
@time Scrypt.pbkdf2_sha256_1(key, buf_len)
@code_typed Scrypt.pbkdf2_sha256_1(key, buf_len)

buffer2 = Scrypt.pbkdf2_sha256_1_0(key, UInt8[], buf_len)

@test buffer == buffer2

i=845254645
tail_reverse = reinterpret(UInt8, [UInt32(i)]) |> reverse
# 4-element Vector{UInt8}:
#  0x32
#  0x61
#  0x8f
#  0xf5

# scrypt:
buffer = Scrypt.pbkdf2_sha256_1(key, salt, Scrypt.bufferlength(parameters))
parallelbuffer = reshape(reinterpret(Scrypt.Salsa512, buffer), (Scrypt.elementblockcount(parameters), parameters.p))

i=1
element = @views reshape(parallelbuffer[:, i], elementblockcount(parameters))

# smix!:
workingbuffer = Scrypt.prepare(element)
src = element

# prepare:
dest = valloc(Scrypt.Salsa512, length(src))
si = 1:length(src)
dj = [2:length(dest); 1]

u32v = Scrypt.uint32view(dest, j)
=#