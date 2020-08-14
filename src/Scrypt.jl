module Scrypt

using Nettle

include("data/ScryptAlgorithm.jl")


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

function smix(element)
    preparedata(workingbuffer, element)
    fillscryptblock(workingbuffer)
end


export ScryptAlgorithm

end