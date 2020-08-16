module Scrypt

using Nettle

include("data/SalsaBlock.jl")
include("data/ScryptParameters.jl")


SALSA_BLOCK_LENGTH_UINT32 = 16

salsa_block_reorder_indexes = [13;  2;  7; 12;  1;  6; 11; 16;  5; 10; 15;  4;  9; 14;  3;  8]
salsa_block_restore_indexes = [ 5;  2; 15; 12;  9;  6;  3; 16; 13; 10;  7;  4;  1; 14; 11;  8]

function scrypt(parameters::ScryptParameters, key::Vector{UInt8}, salt::Vector{UInt8}, derivedkeylength)
    derivedkeylength > 0 || ArgumentError("Must be > 0.") |> throw

    buffer = pbkdf2_sha256_1(key, salt, bufferlength(parameters))
    parallelbuffer = reshape(buffer, (elementlength(parameters), parameters.p))

    for i ∈ 1:parameters.p
        smix!(view(parallelbuffer, :, i), parameters)
    end

    derivedkey = pbkdf2_sha256_1(key, buffer, derivedkeylength)
end

function pbkdf2_sha256_1(key, salt::Vector{UInt8}, derivedkeylength)
    function saltdigest(i, salttail)
        salttail[:] = reinterpret(UInt8, [UInt32(i)]) |> reverse
        digest("sha256", key, salt)
    end

    hashlength = 256 ÷ 8
    blocks = ceil(derivedkeylength ÷ hashlength) |> Int
    lastblockbytes = derivedkeylength - (blocks - 1) * hashlength
    
    salt = [salt; zeros(UInt8, 4)]
    salttail = view(salt, length(salt) - 3:length(salt))
    
    derivedkey = vcat((saltdigest(i, salttail) for i ∈ 1:blocks)...)

    return lastblockbytes < hashlength ? derivedkey[1:end-hashlength+lastblockbytes] : derivedkey
end

prepareblock(block) = reinterpret(SalsaBlock, view(reinterpret(UInt32, block), salsa_block_reorder_indexes))
restoreblock(block) = reinterpret(SalsaBlock, view(reinterpret(UInt32, block), salsa_block_restore_indexes))

function preparedata!(workingbuffer, element)
    workingbuffer[2:end] = vcat((prepareblock(view(element, i:i)) for i ∈ 1:length(element) - 1)...) # hopefully this will optimize to write directly rather than creating an intermediate array
    workingbuffer[1] = prepareblock(view(element, length(element):length(element))) |> first
    ()
end

function restoredata!(element, workingbuffer)
    element[1:end - 1] = vcat((restoreblock(view(workingbuffer, i:i)) for i ∈ 2:length(workingbuffer))...)
    element[end] = restoreblock(view(workingbuffer, 1:1)) |> first
    ()
end

function mixblock!(currentblock, previousblock)
    currentblock[1] = reinterpret(SalsaBlock, reinterpret(UInt128, currentblock) .⊻ reinterpret(UInt128, previousblock)) |> first
    salsa20!(currentblock, 8)
    ()
end

function salsa20!(block, iterations)
    splitblock = reshape(reinterpret(UInt32, block), (4, 4))
    inputblock = copy(splitblock)

    for i ∈ 1:iterations
        splitblock[:, 3] = salsa(splitblock[:, 1], splitblock[:, 2], splitblock[:, 3], 7)
        splitblock[:, 4] = salsa(splitblock[:, 2], splitblock[:, 3], splitblock[:, 4], 9)
        splitblock[:, 1] = salsa(splitblock[:, 3], splitblock[:, 4], splitblock[:, 1], 13)
        splitblock[:, 2] = salsa(splitblock[:, 4], splitblock[:, 1], splitblock[:, 2], 18)

        salsatranspose!(splitblock)
    end

    splitblock .+= inputblock
    block[1] = reinterpret(SalsaBlock, reshape(splitblock, 16)) |> first
    ()
end

function salsatranspose!(block)
    toline3 = block[[2, 3, 4, 1], 1]
    block[:, 1] = block[[4, 1, 2, 3], 3]
    block[:, 3] = toline3
    block[:, 4] = block[[3, 4, 1, 2], 4]
    ()
end

function salsa(addend1::AbstractVector{UInt32}, addend2::AbstractVector{UInt32}, xor_operand::AbstractVector{UInt32}, rotationmagnitude)
    return xor_operand .⊻ bitrotate.(addend1 .+ addend2, rotationmagnitude)
end

function fillscryptblock!(workingbuffer, shufflebuffer, N, r)
    halfblockcount = length(workingbuffer) ÷ 2
    scryptblock = zeros(SalsaBlock, 2 * r, N)

    for i ∈ 1:N
        previousblock = lastblock = view(workingbuffer, 1:1)
        scryptblock[1, i] = copy(previousblock)
        for j ∈ 2:length(workingbuffer)
            currentblock = view(workingbuffer, j:j)
            scryptblock[j, i] = copy(currentblock)
            k = (j - 2) ÷ 2 + 2
            iseven(j) || (k += halfblockcount)
            mixblock!(currentblock, previousblock)
            previousblock = currentblock
            shufflebuffer[k] = copy(currentblock)
        end
        mixblock!(lastblock, previousblock)
        shufflebuffer[1] = copy(lastblock)

        workingbuffer[:] = shufflebuffer
    end
    
    return scryptblock
end

integerify(workingbuffer, N) = reinterpret(UInt32, workingbuffer)[5] % N + 1

function mixwithscryptblock!(workingbuffer, scryptblock, shufflebuffer, N)
    halfblockcount = length(workingbuffer) ÷ 2
    for i ∈ 1:N
        n = integerify(view(workingbuffer, 1:1), N)
        scryptblockelement = view(scryptblock, :, n)
        previousblock = lastblock = view(reinterpret(SalsaBlock, reinterpret(UInt128, view(workingbuffer, 1:1)) .⊻ reinterpret(UInt128, view(scryptblockelement, 1:1))), 1)
        for j ∈ 2:length(workingbuffer)
            currentblock = view(reinterpret(SalsaBlock, reinterpret(UInt128, view(workingbuffer, j:j)) .⊻ reinterpret(UInt128, view(scryptblockelement, j:j))), 1)
            k = (j - 2) ÷ 2 + 2
            iseven(j) || (k += halfblockcount)
            mixblock!(currentblock, previousblock)
            previousblock = currentblock
            shufflebuffer[k] = copy(currentblock)
        end
        mixblock!(lastblock, previousblock)
        shufflebuffer[1] = copy(lastblock)

        workingbuffer[:] = shufflebuffer
    end
end

salsabuffer(parameters::ScryptParameters) = zeros(SalsaBlock, elementblockcount(parameters))

function smix!(element::AbstractVector{UInt8}, parameters::ScryptParameters)
    blockelement = reinterpret(SalsaBlock, element)
    workingbuffer = salsabuffer(parameters)
    shufflebuffer = salsabuffer(parameters)

    preparedata!(workingbuffer, blockelement)
    scryptblock = fillscryptblock!(workingbuffer, shufflebuffer, parameters.N, parameters.r) # verified
    mixwithscryptblock!(workingbuffer, scryptblock, shufflebuffer, parameters.N)
    restoredata!(blockelement, workingbuffer)
end

export scrypt
export ScryptParameters

end