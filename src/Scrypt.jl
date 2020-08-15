module Scrypt

using Nettle

include("data/ScryptAlgorithm.jl")


SALSA_BLOCK_LENGTH_UINT32 = 16

salsa_block_reorder_indexes = [13;  2;  7; 12;  1;  6; 11; 16;  5; 10; 15;  4;  9; 14;  3;  8]
salsa_block_restore_indexes = [ 5;  2; 15; 12;  9;  6;  3; 16;  3; 10;  7;  4;  1; 14; 11;  8]

function scrypt(parameters::ScryptParameters, key, salt::Vector{UInt8}, derivedkeylength)
    derivedkeylength > 0 || ArgumentError("Must be > 0.") |> throw

    buffer = pbkdf2_sha256_1(key, salt, workingbufferlength(parameters))



    derivedkey = pbkdf2_sha256_1(key, buffer, derivedkeylength)
end

function pbkdf2_sha256_1(key, salt::Vector{Uint8}, derivedkeylength)
    function digest(i)
        salt[end] = i
        hexdigest("sha256", key, salt) |> Vector{UInt8}
    end

    hashlength = 256 / 8
    blocks = derivedkeylength / hashlength
    blocks < 256 || ArgumentError("derivedkeylength must be less than 256 bytes.") |> throw
    
    salt = copy(salt)
    push!(0)

    return vcat(digest(i) for i ∈ 1:blocks)
end

element(parameters::ScryptParameters) = zeros(SalsaBlock, elementblockcount(parameters))

prepareblock(block) = reinterpret(SalsaBlock, view(reinterpret(UInt32, reshape(block, 1)), salsa_block_reorder_indexes))
restoreblock(block) = reinterpret(SalsaBlock, view(reinterpret(UInt32, reshape(block, 1)), salsa_block_restore_indexes))

function preparedata!(workingbuffer, element)
    workingbuffer[2:end] = [prepareblock(view(element, i)) for i ∈ [1:length(element) - 1]] # hopefully this will optimize to write directly rather than creating an intermediate array
    workingbuffer[1] = prepareblock(view(element, length(element)))
end

function restoredata!(element, workingbuffer)
    element[1:end - 1] = [restoreblock(view(workingbuffer, i) for i ∈ [2:length(workingbuffer)])]
    element[end] = restoreblock(view(element, 1))
end

function mixblock!(currentblock, previousblock)
    currentblock ⊻= previousblock
    salsa20!(currentblock, 8)
end

function salsa20!(block, iterations)
    splitblock = reshape(reinterpret(UInt32, reshape(block, 1)), 4, 4)
    inputblock = copy(splitblock)

    for i ∈ 1:iterations
        splitblock[:, 3] = salsa(splitblock[:, 1], splitblock[:, 2], splitblock[:, 3], 7)
        splitblock[:, 4] = salsa(splitblock[:, 2], splitblock[:, 3], splitblock[:, 4], 9)
        splitblock[:, 1] = salsa(splitblock[:, 3], splitblock[:, 4], splitblock[:, 1], 13)
        splitblock[:, 2] = salsa(splitblock[:, 4], splitblock[:, 1], splitblock[:, 2], 18)

        splitblock = splitblock'
    end

    splitblock .+= inputblock
end

function salsa(addend1::AbstractVector{UInt32}, addend2::AbstractVector{UInt32}, xor_operand::AbstractVector{UInt32}, rotationmagnitude)
    return xor_operand .⊻ bitrotate.(addend1 .+ addend2, rotationmagnitude)
end

function fillscryptblock!(workingbuffer, shufflebuffer, N, r)
    halfblockcount = length(workingbuffer) ÷ 2
    scryptblock = zeros(SalsaBlock, 2 * r, N)

    for i ∈ 1:N
        scryptblock[1, i] = previousblock = lastblock = view(workingbuffer, 1)
        for j ∈ 2:length(workingbuffer) - 1
            currentblock = view(workingbuffer, j)
            scryptblock[j, i] = currentblock
            k = j ÷ 2 + 1
            k += iseven(j) ? 0 : halfblockcount
            mixblock!(currentblock, previousblock)
            shufflebuffer[k] = previousblock = currentblock
        end
        mixblock!(lastblock, previousblock)
        shufflebuffer[1] = lastblock

        workingbuffer, shufflebuffer = shufflebuffer, workingbuffer
    end
    
    return scryptblock
end

integerify(workingbuffer, N) = reinterpret(UInt32, reshape(workingbuffer, 1))[5] % N

function mix!(workingbuffer, scryptblock, shufflebuffer, N)
    halfblockcount = length(workingbuffer) ÷ 2
    for i ∈ 1:N
        n = integerify(view(workingbuffer, 1), N)
        blockelement = view(scryptblock, :, n)
        previousblock = lastblock = view(workingbuffer, 1) ⊻ view(blockelement, 1)
        for j ∈ 2:length(workingbuffer) - 1
            currentblock = view(workingbuffer, j) ⊻ view(blockelement, j)
            k = j ÷ 2 + 1
            k += iseven(j) ? 0 : halfblockcount
            mixblock!(currentblock, previousblock)
            shufflebuffer[k] = previousblock = currentblock
        end
        mixblock!(lastblock, previousblock)
        shufflebuffer[1] = lastblock

        workingbuffer, shufflebuffer = shufflebuffer, workingbuffer
    end
end

function smix!(element::Vector{SalsaBlock}, parameters::ScryptParameters)
    workingbuffer = element(parameters)
    shufflebuffer = element(parameters)

    preparedata!(workingbuffer, element)
    scryptblock = fillscryptblock!(workingbuffer, shufflebuffer, parameters.N, parameters.r)
    mix!(workingbuffer, scryptblock, shufflebuffer, parameters.N)
    restoredata!(element, workingbuffer)
end





export ScryptAlgorithm

end