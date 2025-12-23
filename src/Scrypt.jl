module Scrypt

using Nettle
using SIMD

include("data/Salsa512.jl")
include("data/ScryptParameters.jl")
include("util.jl")

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
    n = length(src)
    dest = valloc(Salsa512, length(src))
    uint32view(dest, 1) .= uint32view(src, n)[SALSA_BLOCK_REORDER_INDEXES]
    for i ∈ 2:n
        uint32view(dest, i) .= uint32view(src, i - 1)[SALSA_BLOCK_REORDER_INDEXES]
    end
    return dest
end

function restore!(dest::AbstractVector{Salsa512}, src::AbstractVector{Salsa512})
    length(dest) == length(src) || throw(DimensionMismatch("dest and src must have the same length"))
    n = length(src)
    uint32view(dest, n)[SALSA_BLOCK_REORDER_INDEXES] .= uint32view(src, 1)
    for i ∈ 2:n
        uint32view(dest, i - 1)[SALSA_BLOCK_REORDER_INDEXES] .= uint32view(src, i)
    end
end

function fillscryptblock!(workingbuffer::AbstractVector{Salsa512}, shufflebuffer::AbstractVector{Salsa512}, r, N)
    scryptblock = reshape(valloc(Salsa512, 2r * N), (2r, N))
    for i ∈ 1:N
        scryptelement = view(scryptblock, :, i)
        previousblock = lastblock = load_store!(workingbuffer, scryptelement, 1)
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

uint32view(x, i) = @inbounds reinterpret(UInt32, view(x, i:i))
vloadsalsa(x, i) = @inbounds vloada(Vec{16, UInt32}, uint32view(x, i), 1)
vloadsalsant(x, i) = @inbounds vloadnt(Vec{16, UInt32}, uint32view(x, i), 1)
vstoresalsa(v, x, i) = @inbounds vstorea(v, uint32view(x, i), 1)
vstoresalsant(v, x, i) = @inbounds vstorent(v, uint32view(x, i), 1)

function load_store!(workingbuffer::AbstractVector{Salsa512}, scryptelement::AbstractVector{Salsa512}, i)
    block = vloadsalsa(workingbuffer, i)
    vstoresalsant(block, scryptelement, i)
    return block
end

function mixwithscryptblock!(workingbuffer::AbstractVector{Salsa512}, scryptblock, shufflebuffer::AbstractVector{Salsa512}, r, N)
    for i ∈ 1:N
        n = integerify(workingbuffer, N)
        scryptelement = reshape(view(scryptblock, :, n), 2r)

        for j ∈ 1:r # prefetch first half of the element
            vprefetchnt(scryptelement, j)
        end

        previousblock = lastblock = load_xor(workingbuffer, scryptelement, 1)
        for j ∈ 2:2r
            if j ≤ (r + 1) # prefetch one additional block through end
                vprefetchnt(scryptelement, r + j - 1)
            end

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

    lines = splitblock(block)
    for i ∈ 1:iterations
        lines = salsamix(lines)
        lines = salsatranspose(lines)
    end
    block = joinlines(lines)

    block += inputblock
    return block
end

splitblock(block) = (shufflevector(block, Val((0,1,2,3))),
                     shufflevector(block, Val((4,5,6,7))),
                     shufflevector(block, Val((8,9,10,11))),
                     shufflevector(block, Val((12,13,14,15))))

joinlines(lines) = @inbounds shufflevector(shufflevector(lines[1], lines[2], Val((0, 1, 2, 3, 4, 5, 6, 7))),
                                           shufflevector(lines[3], lines[4], Val((0, 1, 2, 3, 4, 5, 6, 7))),
                                           Val((0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15)))

function salsamix(lines)
    line1, line2, line3, line4 = lines
    line3 = salsa(line1, line2, line3, 7)
    line4 = salsa(line2, line3, line4, 9)
    line1 = salsa(line3, line4, line1, 13)
    line2 = salsa(line4, line1, line2, 18)
    return (line1, line2, line3, line4)
end

function salsa(addend1, addend2, xor_operand, rotationmagnitude)
    sum = addend1 + addend2
    rot = (sum << rotationmagnitude) | (sum >>> (sizeof(UInt32) * 8 - rotationmagnitude))
    return xor_operand ⊻ rot
end

function salsatranspose(lines)
    toline3 = @inbounds shufflevector(lines[1], Val((1, 2, 3, 0)))
    line1 = @inbounds shufflevector(lines[3], Val((3, 0, 1, 2)))
    line3 = toline3
    line4 = @inbounds shufflevector(lines[4], Val((2, 3, 0, 1)))
    return @inbounds (line1, lines[2], line3, line4)
end

export scrypt
export ScryptParameters

end