"""
    ScryptElement(r::Int)
    ScryptElement(x::AbstractVector{SalsaBlock})

A 2r vector of 512-bit (64-byte) SalsaBlocks that forms the chunk of data that
scrypt works on at one time. It may either be standalone or may be created from
existing data, including a view into ScryptBlock. Indexing produces SalsaBlock
objects with a view of the underlying data.
"""
mutable struct ScryptElement{T <: AbstractVector{Salsa512}}
    data::T
    r::Int

    ScryptElement(r::Int) = new{Vector{Salsa512}}(Vector{Salsa512}(undef, 2r), r)
    function ScryptElement(r::Int, x::AbstractVector{Salsa512})
        length(x) == 2r || ArgumentError("x must be of length 2r")
        new{typeof(x)}(x, r)
    end
end

function swap!(x::ScryptElement, y::ScryptElement) 
    x.data, y.data = y.data, x.data
    ()
end

import Base.getindex
getindex(x::ScryptElement, i) = SalsaBlock(@view x.data[i:i])

import Base.setindex!
setindex!(x::ScryptElement, y::SalsaBlock, i) = setindex!(x.data, (y |> asblock).data[1], i)
setindex!(x::ScryptElement, y::AbstractVector{SalsaBlock{T}}, r) where {T} =
    x.data[r] .= ((yi |> asblock).data[1] for yi in y)


import Base.length
length(x::ScryptElement) = length(x.data)

import Base.lastindex
lastindex(x::ScryptElement) = length(x)

"""
    prepare(x::ScryptElement)
    restore!(dest::ScryptElement, x::ScryptElement)

The data in the buffer needs to be organized for efficient processing. First,
the last 512-bit (64-byte) block is placed first. Second, each block is
internally rearranged to simplify the Salsa20/8 operations. The data are 
restored to their original positions by restore!().
"""
function prepare(x::ScryptElement)
    y = ScryptElement(x.r)
    y[2:end] = [x[i] |> prepare for i ∈ 1:length(x) - 1]
    y[1] = x[end] |> prepare
    return y
end

function restore!(dest::ScryptElement, x::ScryptElement)
    dest[1:end - 1] = [x[i] |> restore for i ∈ 2:length(x)]
    dest[end] = x[1] |> restore
end
