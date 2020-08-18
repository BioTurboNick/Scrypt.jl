"""
    ScryptBlock(r, N)

Holds the primary data buffer that creates the minimum memory requirement for
the scrypt algorithm. A two-dimensional 2r*N array of 512-bit (64-byte)
SalsaBlock items. Each column of 2r SalsaBlocks in this array forms a
ScryptElement.
"""
struct ScryptBlock <: AbstractArray{SalsaBlock, 2}
    data::Array{SalsaBlock, 2}
    r::Int

    ScryptBlock(r, N) = new(Array{SalsaBlock, 2}(undef, 2r, N), r)
end


getelement(x::ScryptBlock, i) = @views ScryptElement(x.r, x.data[:, i])

import Base.show
show(io::IO, x::ScryptBlock) = show(io, x.data)

import Base.size
size(x::ScryptBlock) = size(x.data)

import Base.getindex
getindex(x::ScryptBlock, i) = getindex(x.data, i)
getindex(x::ScryptBlock, i, j) = getindex(x.data, i, j)