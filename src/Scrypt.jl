module Scrypt

using Nettle
using Nettle.Nettle_jll
using SIMD

include("data/Salsa512.jl")
include("data/ScryptParameters.jl")
include("util.jl")

function scrypt_0(parameters::ScryptParameters, key::Vector{UInt8}, salt::Vector{UInt8}, derivedkeylength::Integer)
    derivedkeylength > 0 || ArgumentError("Must be > 0.") |> throw

    buffer = pbkdf2_sha256_1_0(key, salt, bufferlength(parameters))
    parallelbuffer = reshape(reinterpret(Salsa512, buffer), (elementblockcount(parameters), parameters.p))

    for i ∈ 1:parameters.p
        element = @views reshape(parallelbuffer[:, i], elementblockcount(parameters))
        smix!(element, parameters)
    end

    derivedkey = pbkdf2_sha256_1_0(key, buffer, derivedkeylength)
end

function scrypt(parameters::ScryptParameters, key::Vector{UInt8}, salt::Vector{UInt8}, derivedkeylength::Integer)
    derivedkeylength > 0 || ArgumentError("Must be > 0.") |> throw

    buffer = Scrypt.pbkdf2_sha256_1(key, salt, Scrypt.bufferlength(parameters))
    parallelbuffer = reshape(reinterpret(Scrypt.Salsa512, buffer), (Scrypt.elementblockcount(parameters), parameters.p))

    for i ∈ 1:parameters.p
        element = reshape(@view(parallelbuffer[:, i]), Scrypt.elementblockcount(parameters))
        smix!(element, parameters)
    end

    derivedkey = pbkdf2_sha256_1(key, buffer, derivedkeylength)
end

function scrypt(parameters::ScryptParameters, key::Vector{UInt8}, derivedkeylength::Integer)
    derivedkeylength > 0 || ArgumentError("Must be > 0.") |> throw

    buffer = Scrypt.pbkdf2_sha256_1(key, Scrypt.bufferlength(parameters))
    parallelbuffer = reshape(reinterpret(Scrypt.Salsa512, buffer), (Scrypt.elementblockcount(parameters), parameters.p));
    parallelbuffer_2 = unsafe_wrap(Array{UInt32,3}, Ptr{UInt32}(pointer(buffer)), (16, Scrypt.elementblockcount(parameters), parameters.p));

    workingbuffer_new = Matrix{UInt32}(undef, (16, Scrypt.elementblockcount(parameters)))
    shufflebuffer_new = Matrix{UInt32}(undef, (16, Scrypt.elementblockcount(parameters)))
    scryptblock_new = Array{UInt32, 3}(undef, 16, 2*parameters.r, parameters.N);

    for i ∈ 1:parameters.p
        element = reshape(@view(parallelbuffer[:, i]), Scrypt.elementblockcount(parameters))
        element_new = reshape(@view(parallelbuffer_2[:, :, i]), (16, Scrypt.elementblockcount(parameters)))
        # smix!(element, parameters)
        smix_new!(scryptblock_new, workingbuffer_new, shufflebuffer_new, element_new, parameters)
    end

    derivedkey = pbkdf2_sha256_1(key, buffer, derivedkeylength)
end

const HASH_LENGTH::Int = 256 ÷ 8

function pbkdf2_sha256_1_0(key, salt::Vector{UInt8}, derivedkeylength)
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

function pbkdf2_sha256_1(key::Vector{UInt8}, salt::Vector{UInt8}, derivedkeylength::Int)
    blockcount = cld(derivedkeylength, HASH_LENGTH)::Int
    
    salt_new = copy(salt)
    push!(salt_new, 0x00, 0x00, 0x00, 0x00)
    
    derivedkey::Vector{UInt8} = Vector{UInt8}(undef, (HASH_LENGTH * blockcount)::Int);
    p_derivedkey = pointer(derivedkey)::Ptr{UInt8}

    state = Nettle.HMACState("SHA256", key)
    for i in 1:blockcount
        Scrypt.salt_tail_reverse!(salt_new, i)
        Scrypt.unsafe_digest!(p_derivedkey + (i - 1) * HASH_LENGTH, Csize_t(HASH_LENGTH), Nettle.update!(state, salt_new))
    end
    resize!(derivedkey, derivedkeylength)
    return derivedkey
end

function pbkdf2_sha256_1(key::Vector{UInt8}, derivedkeylength::Int)
    blockcount = cld(derivedkeylength, HASH_LENGTH)::Int
    
    salt = zeros(UInt8, 4)
    
    derivedkey::Vector{UInt8} = Vector{UInt8}(undef, (HASH_LENGTH * blockcount)::Int);
    p_derivedkey = pointer(derivedkey)::Ptr{UInt8}

    state = Nettle.HMACState("SHA256", key)
    for i in 1:blockcount
        Scrypt.salt_tail_reverse!(salt, i)
        Scrypt.unsafe_digest!(p_derivedkey + (i - 1) * HASH_LENGTH, Csize_t(HASH_LENGTH), Nettle.update!(state, salt))
    end
    resize!(derivedkey, derivedkeylength)
    return derivedkey
end

function salt_tail_reverse!(salt::Vector{UInt8}, i::Int)
    # reinterpret(UInt8, [UInt32(i)]) |> reverse
    u32 = UInt32(i)
    @inbounds salt[end] = u32 % UInt8
    u32 >>= 8
    @inbounds salt[end - 1] = u32 % UInt8
    u32 >>= 8
    @inbounds salt[end - 2] = u32 % UInt8
    u32 >>= 8
    @inbounds salt[end - 3] = u32 % UInt8
    nothing
end

function unsafe_digest!(digest_block::Ptr{UInt8}, block_size::Csize_t, state::Nettle.HMACState)
    # @boundscheck checkbounds(digest_block, state.hash_type.digest_size)
    ccall((:nettle_hmac_digest,libnettle), Cvoid, (Ptr{Cvoid},Ptr{Cvoid},Ptr{Cvoid},Ptr{Cvoid}, Csize_t,
        Ptr{UInt8}), state.outer, state.inner, state.state, state.hash_type.ptr, block_size, digest_block)
    return digest_block
end

function smix!(element::AbstractVector{Salsa512}, parameters::ScryptParameters)
    workingbuffer = Scrypt.prepare(element)
    shufflebuffer = valloc(Salsa512, length(workingbuffer))
    scryptblock, workingbuffer, shufflebuffer = fillscryptblock!(workingbuffer, shufflebuffer, parameters.r, parameters.N)
    workingbuffer = mixwithscryptblock!(workingbuffer, scryptblock, shufflebuffer, parameters.r, parameters.N)
    restore!(element, workingbuffer)
end
function smix_new!(scryptblock_new::Array{UInt32, 3}, workingbuffer_new::Matrix{UInt32}, shufflebuffer_new::Matrix{UInt32}, element_new::AbstractArray{UInt32, 2}, parameters::ScryptParameters)
    prepare_new!(workingbuffer_new, element_new)
    scryptblock, workingbuffer, shufflebuffer = fillscryptblock_new!(scryptblock_new, workingbuffer, shufflebuffer, parameters.r, parameters.N)
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
function prepare_new!(dest::Matrix{UInt32}, src::AbstractArray{UInt32, 2})
    ysize = size(src, 2)

    for i in 1:ysize
        j = i == ysize ? 1 : i + 1
        dest[:,j] .= @view src[SALSA_BLOCK_REORDER_INDEXES,i]
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
function restore_new!(dest::AbstractVector{Salsa512}, src::AbstractVector{Salsa512})

    # for (i, j) ∈ zip(si, dj)
    for (i, src_i) in enumerate(src)
        j = i == 1 ? length(dest) : i - 1
        @inbounds dest[j] = src_i
        invpermute!(uint32view(dest, j), SALSA_BLOCK_REORDER_INDEXES)
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
function fillscryptblock_new!(scryptblock_new::Array{UInt32, 3}, workingbuffer_new::AbstractVector{Salsa512}, shufflebuffer_new::AbstractVector{Salsa512}, r, N)
    
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