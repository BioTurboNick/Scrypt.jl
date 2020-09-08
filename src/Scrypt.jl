module Scrypt

using Nettle
using SIMD

include("data/Salsa512.jl")
include("data/ScryptParameters.jl")

function scrypt(parameters::ScryptParameters, key::Vector{UInt8}, salt::Vector{UInt8}, derivedkeylength)
    derivedkeylength > 0 || ArgumentError("Must be > 0.") |> throw

    buffer = pbkdf2_sha256_1(key, salt, bufferlength(parameters))
    parallelbuffer = reshape(reinterpret(Salsa512, buffer), (elementblockcount(parameters), parameters.p))

    for i ∈ 1:parameters.p
        element = @views reshape(parallelbuffer[:, i], elementblockcount(parameters))
        smix!(element, parameters)
    end

    derivedkey = pbkdf2_sha256_1(key, buffer, derivedkeylength)
end

const HASH_LENGTH = 256 ÷ 8

function pbkdf2_sha256_1(key, salt::Vector{UInt8}, derivedkeylength)
    blockcount = cld(derivedkeylength, HASH_LENGTH)
    lastblockbytes = derivedkeylength - (blockcount - 1) * HASH_LENGTH
    
    salt = [salt; zeros(UInt8, 4)]
    salttail = view(salt, length(salt) - 3:length(salt))
    
    derivedkey = Matrix{UInt8}(undef, HASH_LENGTH, blockcount)

    for i ∈ 1:blockcount
        salttail[:] = reinterpret(UInt8, [UInt32(i)]) |> reverse
        derivedkey[:, i] = digest("sha256", key, salt)
    end

    derivedkey = reshape(derivedkey, blockcount * HASH_LENGTH)[1:derivedkeylength]
    return derivedkey
end

function smix!(element::AbstractVector{Salsa512}, parameters::ScryptParameters)
    workingbuffer = prepare(element)
    shufflebuffer = valloc(Salsa512, length(workingbuffer))
    scryptblock, workingbuffer, shufflebuffer = fillscryptblock!(workingbuffer, shufflebuffer, parameters.r, parameters.N)
    workingbuffer = mixwithscryptblock!(workingbuffer, scryptblock, shufflebuffer, parameters.r, parameters.N)
    restore!(element, workingbuffer)
end

const SALSA_BLOCK_REORDER_INDEXES = [13;  2;  7; 12;  1;  6; 11; 16;  5; 10; 15;  4;  9; 14;  3;  8]

function prepare(src::AbstractVector{Salsa512})
    dest = valloc(Salsa512, length(src))
    si = 1:length(src)
    dj = [2:length(dest); 1]

    for (i, j) ∈ zip(si, dj)
        dest[j] = src[i]
        permute!(uint32view(dest, j), SALSA_BLOCK_REORDER_INDEXES)
    end

    return dest
end #permute! is no faster than explicit vectorization, even with a few extra allocations

function restore!(dest::AbstractVector{Salsa512}, src::AbstractVector{Salsa512})
    si = 1:length(src)
    dj = [length(dest); 1:length(dest) - 1]

    for (i, j) ∈ zip(si, dj)
        dest[j] = src[i]
        invpermute!(uint32view(dest, j), SALSA_BLOCK_REORDER_INDEXES)
    end
end

function fillscryptblock!(workingbuffer::AbstractVector{Salsa512}, shufflebuffer::AbstractVector{Salsa512}, r, N)
    scryptblock = reshape(valloc(Salsa512, 2r * N), (2r, N))
    for i ∈ 1:N
        scryptelement = view(scryptblock, :, i)
        previousblock = lastblock = block = load_store!(workingbuffer, scryptelement, 1)
        for j ∈ 2:2r
            block = load_store!(workingbuffer, scryptelement, j)
            block = mixblock_shuffle_store!(block, previousblock, shufflebuffer, shuffleposition(j, r))
            previousblock = block
        end
        mixblock_shuffle_store!(lastblock, previousblock, shufflebuffer, 1)
        workingbuffer, shufflebuffer = shufflebuffer, workingbuffer
    end
    return scryptblock, workingbuffer, shufflebuffer
end

shuffleposition(j, halfblockcount) = (j - 2) ÷ 2 + 2 + (iseven(j) ? 0 : halfblockcount)

import Base.stride
import Base.strides

function stride(a::Base.ReinterpretArray, i::Int)
    a.parent isa StridedArray || ArgumentError("Parent must be strided.") |> throw
    if i > ndims(a)
        return length(a)
    end
    s = 1
    for n = 1:(i-1)
        s *= size(a, n)
    end
    return s
end

function strides(a::Base.ReinterpretArray)
    a.parent isa StridedArray || ArgumentError("Parent must be strided.") |> throw
    Base.size_to_strides(1, size(a)...)
end

uint32view(x, i) = reinterpret(UInt32, view(x, i:i))
vloadsalsa(x, i) = vloada(Vec{16, UInt32}, uint32view(x, i), 1)
vloadsalsant(x, i) = vloadnt(Vec{16, UInt32}, uint32view(x, i), 1)
vstoresalsa(v, x, i) = vstorea(v, uint32view(x, i), 1)

function load_store!(workingbuffer::AbstractVector{Salsa512}, scryptelement::AbstractVector{Salsa512}, i)
    block = vloadsalsa(workingbuffer, i)
    vstoresalsa(block, scryptelement, i)
    return block
end

function mixwithscryptblock!(workingbuffer::AbstractVector{Salsa512}, scryptblock, shufflebuffer::AbstractVector{Salsa512}, r, N)
    for i ∈ 1:N
        n = integerify(workingbuffer, N)
        scryptelement = reshape(view(scryptblock, :, n), 2r)
        previousblock = lastblock = block = load_xor(workingbuffer, scryptelement, 1)
        for j ∈ 2:2r
            block = load_xor(workingbuffer, scryptelement, j)
            block = mixblock_shuffle_store!(block, previousblock, shufflebuffer, shuffleposition(j, r))
            previousblock = block
        end
        mixblock_shuffle_store!(lastblock, previousblock, shufflebuffer, 1)
        workingbuffer, shufflebuffer = shufflebuffer, workingbuffer
    end
    return workingbuffer
end

integerify(x::AbstractVector{Salsa512}, N) = uint32view(x, 1)[5] % N + 1

function load_xor(workingbuffer::AbstractVector{Salsa512}, scryptelement::AbstractVector{Salsa512}, i)
    block = vloadsalsa(workingbuffer, i)
    block ⊻= vloadsalsant(scryptelement, i)
    return block
end

function mixblock_shuffle_store!(block, previousblock, shufflebuffer, i)
    block ⊻= previousblock
    block = salsa20(block, 8)
    vstoresalsa(block, shufflebuffer, i)
    return block
end

function salsa20(block, iterations)
    inputblock = block

    splitblock = [shufflevector(block, Val((0,1,2,3))),
                    shufflevector(block, Val((4,5,6,7))),
                    shufflevector(block, Val((8,9,10,11))),
                    shufflevector(block, Val((12,13,14,15)))]

    for i ∈ 1:iterations
        salsamix!(splitblock)
        salsatranspose!(splitblock)
    end

    block = shufflevector(shufflevector(splitblock[1], splitblock[2], Val((0, 1, 2, 3, 4, 5, 6, 7))),
                          shufflevector(splitblock[3], splitblock[4], Val((0, 1, 2, 3, 4, 5, 6, 7))),
                          Val((0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15)))

    block += inputblock
    return block
end

function salsamix!(block)
    block[3] = salsa(block[1], block[2], block[3], 7)
    block[4] = salsa(block[2], block[3], block[4], 9)
    block[1] = salsa(block[3], block[4], block[1], 13)
    block[2] = salsa(block[4], block[1], block[2], 18)
    ()
end

function salsa(addend1, addend2, xor_operand, rotationmagnitude)
    sum = addend1 + addend2
    rot = (sum << rotationmagnitude) | (sum >>> (sizeof(UInt32) * 8 - rotationmagnitude))
    return xor_operand ⊻ rot
end

function salsatranspose!(block)
    toline3 = shufflevector(block[1], Val((1, 2, 3, 0)))
    block[1] = shufflevector(block[3], Val((3, 0, 1, 2)))
    block[3] = toline3
    block[4] = shufflevector(block[4], Val((2, 3, 0, 1)))
    ()
end

export scrypt
export ScryptParameters

end