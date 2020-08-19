module Scrypt

using Nettle
using SIMD

include("data/Salsa512.jl")
include("data/SalsaBlock.jl")
include("data/ScryptElement.jl")
include("data/ScryptBlock.jl")
include("data/ScryptParameters.jl")

function scrypt(parameters::ScryptParameters, key::Vector{UInt8}, salt::Vector{UInt8}, derivedkeylength)
    derivedkeylength > 0 || ArgumentError("Must be > 0.") |> throw

    buffer = pbkdf2_sha256_1(key, salt, bufferlength(parameters))
    parallelbuffer = reshape(reinterpret(Salsa512, buffer), (elementblockcount(parameters), parameters.p))

    for i ∈ 1:parameters.p
        element = @views ScryptElement(parameters.r, reshape(parallelbuffer[:, i], elementblockcount(parameters)))
        smix!(element, parameters)
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

function smix!(element::ScryptElement, parameters::ScryptParameters)
    workingbuffer = prepare(element)
    shufflebuffer = ScryptElement(parameters.r)
    scryptblock = fillscryptblock!(workingbuffer, shufflebuffer, parameters.r, parameters.N)
    mixwithscryptblock!(workingbuffer, scryptblock, shufflebuffer, parameters.r, parameters.N)
    restore!(element, workingbuffer)
end

function fillscryptblock!(workingbuffer, shufflebuffer, r, N)
    scryptblock = ScryptBlock(r, N)
    halfblocklength = r

    for i ∈ 1:N
        previousblock = lastblock = workingbuffer[1]
        blockelement = scryptblock[i]
        blockelement[1] = previousblock
        for j ∈ 2:length(workingbuffer)
            blockelement[j] = currentblock = workingbuffer[j]
            k = shuffleposition(j, r)
            mixblock!(currentblock, previousblock)
            shufflebuffer[k] = previousblock = currentblock
        end
        mixblock!(lastblock, previousblock)
        shufflebuffer[1] = lastblock

        swap!(workingbuffer, shufflebuffer)
    end
    
    return scryptblock
end

function mixwithscryptblock!(workingbuffer, scryptblock, shufflebuffer, r, N)
    halfblocklength = r
    for i ∈ 1:N
        n = integerify(workingbuffer, N)
        blockelement = scryptblock[n]
        xor!(workingbuffer[1], blockelement[1])
        previousblock = lastblock = workingbuffer[1]
        for j ∈ 2:length(workingbuffer)
            xor!(workingbuffer[j], blockelement[j])
            currentblock = workingbuffer[j]
            k = shuffleposition(j, r)
            mixblock!(currentblock, previousblock)
            shufflebuffer[k] = previousblock = currentblock
        end
        mixblock!(lastblock, previousblock)
        shufflebuffer[1] = lastblock

        swap!(workingbuffer, shufflebuffer)
    end
end

integerify(x::ScryptElement, N) = asintegers(x[1])[5] % N + 1

shuffleposition(j, halfblockcount) = (j - 2) ÷ 2 + 2 + (iseven(j) ? 0 : halfblockcount)

function mixblock!(currentblock, previousblock)
    xor!(currentblock, previousblock)
    salsa20!(currentblock, 8)
    ()
end

const SALSA_VECTOR_INDEXES = (1,5,9,13)

function salsa20!(block, iterations)
    blockdata = @views asintegers(block).data[:]
    splitblock = [vload(Vec{4, UInt32}, blockdata, i) for i ∈ SALSA_VECTOR_INDEXES]
    inputblock = copy(splitblock)

    for i ∈ 1:iterations
        salsamix!(splitblock)
        salsatranspose!(splitblock)
    end

    splitblock += inputblock

    for i ∈ 1:4
        vstore(splitblock[i], blockdata, SALSA_VECTOR_INDEXES[i])
    end
    ()
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