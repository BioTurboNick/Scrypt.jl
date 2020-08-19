module Scrypt

using Nettle
using StaticArrays

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

function salsa20!(block, iterations)
    splitblock = copystatic(block)
    inputblock = copy(splitblock)

    for i ∈ 1:iterations
        salsamix!(splitblock)
        salsatranspose!(splitblock)
    end

    splitblock .+= inputblock
    copyto!(block, splitblock)
    ()
end

function salsamix!(block)
    for i ∈ 1:4
        block[i, 3] = salsa(block[i, 1], block[i, 2], block[i, 3], 7)
        block[i, 4] = salsa(block[i, 2], block[i, 3], block[i, 4], 9)
        block[i, 1] = salsa(block[i, 3], block[i, 4], block[i, 1], 13)
        block[i, 2] = salsa(block[i, 4], block[i, 1], block[i, 2], 18)
    end
end

const line3selector = [2, 3, 4, 1]
const line1selector = [4, 1, 2, 3]
const line4selector = [3, 4, 1, 2]

function salsatranspose!(block)
    toline3 = block[line3selector, 1]
    block[:, 1] = block[line1selector, 3]
    block[:, 3] = toline3
    block[:, 4] = block[line4selector, 4]
    ()
end

function salsa(addend1::AbstractVector{UInt32}, addend2::AbstractVector{UInt32}, xor_operand::AbstractVector{UInt32}, rotationmagnitude)
    return xor_operand .⊻ bitrotate.(addend1 .+ addend2, rotationmagnitude)
end

salsa(addend1::UInt32, addend2::UInt32, xor_operand::UInt32, rotationmagnitude) =
    xor_operand ⊻ bitrotate(addend1 + addend2, rotationmagnitude)


export scrypt
export ScryptParameters

end