module Scrypt

using Nettle

include("data/SalsaBlock.jl")
include("data/ScryptElement.jl")
include("data/ScryptBlock.jl")
include("data/ScryptParameters.jl")

function scrypt(parameters::ScryptParameters, key::Vector{UInt8}, salt::Vector{UInt8}, derivedkeylength)
    derivedkeylength > 0 || ArgumentError("Must be > 0.") |> throw

    buffer = pbkdf2_sha256_1(key, salt, bufferlength(parameters))
    parallelbuffer = reshape(reinterpret(SalsaBlock, buffer), (elementblockcount(parameters), parameters.p))

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
        previousblock = lastblock = view(workingbuffer, 1:1)
        blockelement = getelement(scryptblock, i)
        blockelement[1] = previousblock |> first
        for j ∈ 2:length(workingbuffer)
            currentblock = view(workingbuffer, j:j)
            blockelement[j] = currentblock |> first
            k = (j - 2) ÷ 2 + 2
            iseven(j) || (k += halfblocklength)
            mixblock!(currentblock, previousblock)
            previousblock = currentblock
            shufflebuffer[k] = currentblock |> first
        end
        mixblock!(lastblock, previousblock)
        shufflebuffer[1] = lastblock |> first

        swap!(workingbuffer, shufflebuffer)
    end
    
    return scryptblock
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

function mixwithscryptblock!(workingbuffer, scryptblock, shufflebuffer, r, N)
    halfblocklength = r
    for i ∈ 1:N
        n = integerify(workingbuffer, N)
        blockelement = getelement(scryptblock, n)
        previousblock = lastblock = reinterpret(SalsaBlock, reinterpret(UInt128, view(workingbuffer, 1:1)) .⊻ reinterpret(UInt128, view(blockelement, 1:1)))
        for j ∈ 2:length(workingbuffer)
            currentblock = reinterpret(SalsaBlock, reinterpret(UInt128, view(workingbuffer, j:j)) .⊻ reinterpret(UInt128, view(blockelement, j:j)))
            k = (j - 2) ÷ 2 + 2
            iseven(j) || (k += halfblocklength)
            mixblock!(currentblock, previousblock)
            previousblock = currentblock
            shufflebuffer[k] = currentblock |> first
        end
        mixblock!(lastblock, previousblock)
        shufflebuffer[1] = lastblock |> first

        swap!(workingbuffer, shufflebuffer)
    end
end

integerify(x::ScryptElement, N) = asintegers(x[1])[5] % N + 1

export scrypt
export ScryptParameters

end