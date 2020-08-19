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
end
