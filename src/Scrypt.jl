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
    # parallelbuffer = reshape(reinterpret(Scrypt.Salsa512, buffer), (Scrypt.elementblockcount(parameters), parameters.p))
    parallelbuffer = unsafe_wrap(Array{UInt32,3}, Ptr{UInt32}(pointer(buffer)), (16, Scrypt.elementblockcount(parameters), parameters.p));
    workingbuffer_new = Matrix{UInt32}(undef, (16, Scrypt.elementblockcount(parameters)))
    shufflebuffer_new = Matrix{UInt32}(undef, (16, Scrypt.elementblockcount(parameters)))
    scryptblock_new = Array{UInt32,3}(undef, 16, 2*parameters.r, parameters.N);
    for i ∈ 1:parameters.p
        # element = reshape(@view(parallelbuffer[:, i]), Scrypt.elementblockcount(parameters))
        # smix!(element, parameters)
        element_new = reshape(@view(parallelbuffer[:, :, i]), (16, Scrypt.elementblockcount(parameters)))
        Scrypt.smix_new!(scryptblock_new, workingbuffer_new, shufflebuffer_new, element_new, parameters)

    end

    derivedkey = pbkdf2_sha256_1(key, buffer, derivedkeylength)
end

function scrypt(parameters::ScryptParameters, key::Vector{UInt8}, derivedkeylength::Integer)
    derivedkeylength > 0 || ArgumentError("Must be > 0.") |> throw

    # buffer = Scrypt.pbkdf2_sha256_1(key, Scrypt.bufferlength(parameters))
    # parallelbuffer = reshape(reinterpret(Scrypt.Salsa512, buffer), (Scrypt.elementblockcount(parameters), parameters.p));

    buffer = Scrypt.pbkdf2_sha256_1(key, Scrypt.bufferlength(parameters))
    parallelbuffer = unsafe_wrap(Array{UInt32,3}, Ptr{UInt32}(pointer(buffer)), (16, Scrypt.elementblockcount(parameters), parameters.p));

    workingbuffer_new = Matrix{UInt32}(undef, (16, Scrypt.elementblockcount(parameters)))
    shufflebuffer_new = Matrix{UInt32}(undef, (16, Scrypt.elementblockcount(parameters)))
    scryptblock_new = Array{UInt32,3}(undef, 16, 2*parameters.r, parameters.N);
    tmp = Vector{UInt32}(undef, 4);

    for i ∈ 1:parameters.p
        # element = reshape(@view(parallelbuffer[:, i]), Scrypt.elementblockcount(parameters))
        element_new = reshape(@view(parallelbuffer[:, :, i]), (16, Scrypt.elementblockcount(parameters)))
        # smix!(element, parameters)
        Scrypt.smix_new!(scryptblock_new, workingbuffer_new, shufflebuffer_new, element_new, parameters)
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
    workingbuffer = Scrypt.prepare(element) #ok
    shufflebuffer = valloc(Salsa512, length(workingbuffer))
    scryptblock, workingbuffer, shufflebuffer = Scrypt.fillscryptblock!(workingbuffer, shufflebuffer, parameters.r, parameters.N)
    workingbuffer = mixwithscryptblock!(workingbuffer, scryptblock, shufflebuffer, parameters.r, parameters.N)
    restore!(element, workingbuffer)
end
function smix_new!(scryptblock_new::Array{UInt32, 3}, workingbuffer_new::Matrix{UInt32}, shufflebuffer_new::Matrix{UInt32}, element_new::AbstractArray{UInt32, 2}, parameters::ScryptParameters)
    Scrypt.prepare_new!(workingbuffer_new, element_new) #ok
    scryptblock_new, workingbuffer_new, shufflebuffer_new = Scrypt.fillscryptblock_new!(scryptblock_new, workingbuffer_new, shufflebuffer_new, parameters.r, parameters.N)
    workingbuffer_new = mixwithscryptblock_new!(workingbuffer_new, scryptblock_new, shufflebuffer_new, parameters.r, parameters.N)
    restore_new!(element_new, workingbuffer_new)
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

    @inbounds dest[:, 1] .= @view src[SALSA_BLOCK_REORDER_INDEXES, ysize]
    @inbounds for i in 1:ysize-1
        dest[:, i+1] .= @view src[SALSA_BLOCK_REORDER_INDEXES, i]
    end

    return dest
end

function restore!(dest::AbstractVector{Salsa512}, src::AbstractVector{Salsa512})
    si = 1:length(src)
    dj = [length(dest); 1:length(dest) - 1]

    for (i, j) ∈ zip(si, dj)
        dest[j] = src[i]
        invpermute!(uint32view(dest, j), SALSA_BLOCK_REORDER_INDEXES)
    end
end
function restore_new!(dest::AbstractMatrix{UInt32}, src::AbstractMatrix{UInt32})

    # for (i, j) ∈ zip(si, dj)
    @inbounds dest[SALSA_BLOCK_REORDER_INDEXES, end] .= @view src[:, 1]
    ysize = size(src, 2)
    @inbounds for i in 2:ysize
         dest[SALSA_BLOCK_REORDER_INDEXES, i-1] .= @view src[:, i]
    end
    return dest
end

function fillscryptblock!(workingbuffer::AbstractVector{Salsa512}, shufflebuffer::AbstractVector{Salsa512}, r, N)
    scryptblock = reshape(valloc(Salsa512, 2r * N), (2r, N))
    for i ∈ 1:N
        scryptelement = view(scryptblock, :, i)
        previousblock = lastblock = Scrypt.load_store!(workingbuffer, scryptelement, 1)
        # workingbuffer[1] -> lastblock, previousblock, scryptelement[1]
        # <16 x UInt32>[0xfc2fc2a5, 0x2f2acbb4, 0x6e9e384a, 0xaee24898, 0xf94480b6, 0x5d55cc33, 0xb4669af9, 0xdef13833, 0xac0eda9d, 0x4324a8a2, 0x060492e5, 0x37c7b6dd, 0xcd46de96, 0x143b4810, 0xafc7723d, 0xc8502d97]
        for j ∈ 2:2r
            block = Scrypt.load_store!(workingbuffer, scryptelement, j)
            # <16 x UInt32>[0xcc3ff8bc, 0xfd1527f6, 0x110c876d, 0x721f4f24, 0x102f23c1, 0xa57b723b, 0x74027a85, 0xafef28b2, 0x10cf339b, 0xa3c80756, 0x7b95c39d, 0xa17c03a2, 0xc7746910, 0x105c158e, 0xc0e76aa0, 0xaba290f2]
            block = Scrypt.mixblock_shuffle_store!(block, previousblock, shufflebuffer, Scrypt.shuffleposition(j, r))
            # block = <16 x UInt32>[0xc4c0f369, 0x117e32d9, 0x01621216, 0x787e69e8, 0x81b2bac0, 0x012fcc7a, 0xba1c59db, 0x471b3e6f, 0xc39af7d6, 0x542bb196, 0xcb46c87b, 0x32d6f806, 0x956746fc, 0xa23f17ca, 0x9b588ebf, 0x3ae8a61e]
            # previous block not changed
            # shufflebuffer[2] = 0x3ae8a61e9b588ebfa23f17ca956746fc32d6f806cb46c87b542bb196c39af7d6471b3e6fba1c59db012fcc7a81b2bac0787e69e801621216117e32d9c4c0f369
            # workingbuffer[2] = scryptelement[2] = 0xaba290f2c0e76aa0105c158ec7746910a17c03a27b95c39da3c8075610cf339bafef28b274027a85a57b723b102f23c1721f4f24110c876dfd1527f6cc3ff8bc
            previousblock = block
        end
        Scrypt.mixblock_shuffle_store!(lastblock, previousblock, shufflebuffer, 1)
        workingbuffer, shufflebuffer = shufflebuffer, workingbuffer
    end
    return scryptblock, workingbuffer, shufflebuffer
end
function fillscryptblock_new!(scryptblock_new::Array{UInt32, 3}, workingbuffer_new::Matrix{UInt32}, shufflebuffer_new::Matrix{UInt32}, r, N) 
    # TODO: check for duplication later
    previousblock_new = Vector{UInt32}(undef, 16);
    block_new = Vector{UInt32}(undef, 16);
    #=
    inplace edit: block_new (workingbuffer_new), shufflebuffer_new[:,i] (stored as final)
    not edit: `previousblock_new`
    =#
    @inbounds for i ∈ 1:N
        scryptelement_new = view(scryptblock_new, :, :, i)
        # previousblock = lastblock = load_store!(workingbuffer, scryptelement, 1)
        last_block_new = @view workingbuffer_new[:, 1]
        scryptelement_new[:, 1] .= last_block_new
        previousblock_new .= last_block_new
        @inbounds for j ∈ 2:2r
            # block = load_store!(workingbuffer, scryptelement, j)
            block_new .= @view workingbuffer_new[:, j] #ok
            scryptelement_new[:, j] .= block_new

            Scrypt.mixblock_shuffle_store_new!(block_new, previousblock_new, shufflebuffer_new, Scrypt.shuffleposition(j, r))
            # block_new, shufflebuffer_new NOT OK
            # previousblock_new, workingbuffer_new ok
            previousblock_new .= block_new
        end
        block_new .= @view workingbuffer_new[:, 1]
        Scrypt.mixblock_shuffle_store_new!(block_new, previousblock_new, shufflebuffer_new, 1)
        workingbuffer_new, shufflebuffer_new = shufflebuffer_new, workingbuffer_new
    end
    return scryptblock_new, workingbuffer_new, shufflebuffer_new
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
        n = Scrypt.integerify(workingbuffer, N)
        scryptelement = reshape(view(scryptblock, :, n), 2r)

        for j ∈ 1:r # prefetch first half of the element
            vprefetchnt(scryptelement, j)
        end

        previousblock = lastblock = Scrypt.load_xor(workingbuffer, scryptelement, 1)
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
function mixwithscryptblock_new!(workingbuffer_new::Matrix{UInt32}, scryptblock_new::Array{UInt32,3}, shufflebuffer_new::Matrix{UInt32}, r::Int, N::Int)
    previousblock_new = Vector{UInt32}(undef, 16);
    lastblock_new = Vector{UInt32}(undef, 16);
    block_new = Vector{UInt32}(undef, 16);
    @inbounds for i ∈ 1:N
        n = Scrypt.integerify(workingbuffer_new, N)
        scryptelement_new = view(scryptblock_new, :, :, n)

        # for j ∈ 1:r # prefetch first half of the element
        #     vprefetchnt(scryptelement_new, j)
        # end

        @inbounds for m in 1:16  # load_xor
            previousblock_new[m] = lastblock_new[m] = workingbuffer_new[m, 1] ⊻ scryptelement_new[m, 1]
        end

        for j ∈ 2:2r
            # if j ≤ (r + 1) # prefetch one additional block through end
            #     vprefetchnt(scryptelement, r + j - 1)
            # end

            @inbounds for m in 1:16
                block_new[m] = workingbuffer_new[m, j] ⊻ scryptelement_new[m, j]
            end

            block_new = mixblock_shuffle_store_new!(block_new, previousblock_new, shufflebuffer_new, shuffleposition(j, r))
            previousblock_new .= block_new
        end
        mixblock_shuffle_store_new!(lastblock_new, previousblock_new, shufflebuffer_new, 1)
        workingbuffer_new, shufflebuffer_new = shufflebuffer_new, workingbuffer_new
    end
    return workingbuffer_new
end

integerify(x::AbstractVector{Salsa512}, N) = uint32view(x, 1)[5] % N + 1
integerify(x::Matrix{UInt32}, N) = @inbounds x[5,1] % N + 1

function load_xor(workingbuffer::AbstractVector{Salsa512}, scryptelement::AbstractVector{Salsa512}, i)
    block = vloadsalsa(workingbuffer, i)
    block ⊻= vloadsalsant(scryptelement, i)
    return block
end

function mixblock_shuffle_store!(block, previousblock, shufflebuffer, i)
    block ⊻= previousblock
    # <16 x UInt32>[0x30103a19, 0xd23fec42, 0x7f92bf27, 0xdcfd07bc, 0xe96ba377, 0xf82ebe08, 0xc064e07c, 0x711e1081, 0xbcc1e906, 0xe0ecaff4, 0x7d915178, 0x96bbb57f, 0x0a32b786, 0x04675d9e, 0x6f20189d, 0x63f2bd65]
    block = salsa20(block, 8)
    # block_sasa = Scrypt.salsa20(block, 8)
    # <16 x UInt32>[0xc4c0f369, 0x117e32d9, 0x01621216, 0x787e69e8, 0x81b2bac0, 0x012fcc7a, 0xba1c59db, 0x471b3e6f, 0xc39af7d6, 0x542bb196, 0xcb46c87b, 0x32d6f806, 0x956746fc, 0xa23f17ca, 0x9b588ebf, 0x3ae8a61e]
    vstoresalsa(block, shufflebuffer, i)
    return block
end
"""
inplace edit: `block_new`, `shufflebuffer_new[:,i]`
not edit: `previousblock_new`
"""
function mixblock_shuffle_store_new!(block_new, previousblock_new, shufflebuffer_new, i)
    block_new .⊻= previousblock_new
    # block_new_good = deepcopy(block_new)
    salsa20_new!(shufflebuffer_new, i, block_new, 8)
    return block_new
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
function salsa20_new!(shufflebuffer_new, i::Int, block_new::Vector{UInt32}, iterations::Int)
    @inbounds shufflebuffer_new[:, i] = block_new
    # lines = splitblock(block_new) # convert to tuple of 4 vectors: 1:4,5:8,9:12,13:16
    line1 = @inbounds @view shufflebuffer_new[1:4, i]
    line2 = @inbounds @view shufflebuffer_new[5:8, i]
    line3 = @inbounds @view shufflebuffer_new[9:12, i]
    line4 = @inbounds @view shufflebuffer_new[13:16, i]
    block_shufflebuffer = @inbounds @view shufflebuffer_new[:, i]
    for _ ∈ 1:iterations
        salsamix!(line1, line2, line3, line4)
        salsatranspose!(block_shufflebuffer)
    end
    block_new .+= block_shufflebuffer
    block_shufflebuffer .= block_new

end

splitblock(block) = (shufflevector(block, Val((0,1,2,3))),
                     shufflevector(block, Val((4,5,6,7))),
                     shufflevector(block, Val((8,9,10,11))),
                     shufflevector(block, Val((12,13,14,15))))

joinlines(lines) = @inbounds shufflevector(shufflevector(lines[1], lines[2], Val((0, 1, 2, 3, 4, 5, 6, 7))),
                                           shufflevector(lines[3], lines[4], Val((0, 1, 2, 3, 4, 5, 6, 7))),
                                           Val((0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15)))

function salsamix(lines::NTuple{4, Vec{4, UInt32}})
    line1, line2, line3, line4 = lines
    line3 = salsa(line1, line2, line3, 7)
    line4 = salsa(line2, line3, line4, 9)
    line1 = salsa(line3, line4, line1, 13)
    line2 = salsa(line4, line1, line2, 18)
    return (line1, line2, line3, line4)
end
function salsamix!(line1::T, line2::T, line3::T, line4::T) where T<:AbstractArray
    line3 = salsa!(line1, line2, line3, 7)
    line4 = salsa!(line2, line3, line4, 9)
    line1 = salsa!(line3, line4, line1, 13)
    line2 = salsa!(line4, line1, line2, 18)
end # ok


function salsa(addend1::Vec{4, UInt32}, addend2::Vec{4, UInt32}, xor_operand::Vec{4, UInt32}, rotationmagnitude::Int)
    sum = addend1 + addend2
    rot = (sum << rotationmagnitude) | (sum >>> (sizeof(UInt32) * 8 - rotationmagnitude))
    return xor_operand ⊻ rot
end
@eval function salsa!(addend1::T, addend2::T, xor_operand::T, rotationmagnitude::Int) where T<:AbstractArray
    one2four = eachindex(xor_operand)
    idx = 0
    @inbounds while idx < 4
        i = Base.simd_index(one2four, 0, idx)
        sumtmp = addend1[i] + addend2[i]
        xor_operand[i] ⊻= sumtmp << rotationmagnitude | sumtmp >>> (32 - rotationmagnitude)
        idx += 1
        $(Expr(:loopinfo, Symbol("julia.simdloop"), Symbol("julia.ivdep")))
    end

    # @simd ivdep for i in eachindex(xor_operand)
    #     sumtmp = addend1[i] + addend2[i]
    #     xor_operand[i] ⊻= (sumtmp << rotationmagnitude) | (sumtmp >>> (32 - rotationmagnitude))
    # end
    return xor_operand
end

function salsatranspose(lines::NTuple{4, Vec{4, UInt32}})
    toline3 = @inbounds shufflevector(lines[1], Val((1, 2, 3, 0)))
    line1 = @inbounds shufflevector(lines[3], Val((3, 0, 1, 2)))
    line3 = toline3
    line4 = @inbounds shufflevector(lines[4], Val((2, 3, 0, 1)))
    return @inbounds (line1, lines[2], line3, line4)
end
# const SALSA_TRANSPOSE_INDEXES = [
#     12,9,10,11,
#     5,6,7,8,
#     2,3,4,1,
#     15,16,13,14
# ]
function salsatranspose!(v::AbstractVector{UInt32})
    @inbounds begin
        a1 = v[1]
        a2 = v[2]
        a3 = v[3]
        a4 = v[4]
        # 5:8 not changed
        a9 = v[9]
        a10 = v[10]
        a11 = v[11]
        a12 = v[12]
        a13 = v[13]
        a14 = v[14]
        a15 = v[15]
        a16 = v[16]
        v[1] = a12
        v[2] = a9
        v[3] = a10
        v[4] = a11
        # 5:8 not changed
        v[9] = a2
        v[10] = a3
        v[11] = a4
        v[12] = a1
        v[13] = a15
        v[14] = a16
        v[15] = a13
        v[16] = a14
    end
    v
end


export scrypt
export ScryptParameters

end