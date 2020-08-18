"""
    ScryptElement(r::Int)
    ScryptElement(x::AbstractVector{SalsaBlock})

A 2r vector of 512-bit (64-byte) SalsaBlocks that forms the chunk of data that
scrypt works on at one time. It may either be standalone or may be created from
existing data, including a view into ScryptBlock.
"""
mutable struct ScryptElement{T <: AbstractVector{SalsaBlock}}
    data::T
    r::Int

    ScryptElement(r::Int) = new{Vector{SalsaBlock}}(Vector{SalsaBlock}(undef, 2r), r)
    function ScryptElement(r::Int, x::AbstractVector{SalsaBlock})
        length(x) == 2r || ArgumentError("x must be of length 2r")
        new{typeof(x)}(x, r)
    end
end

function swap!(x::ScryptElement, y::ScryptElement) 
    x.data, y.data = y.data, x.data
    ()
end

import Base.getindex
getindex(x::ScryptElement, i) = getindex(x.data, i)

import Base.setindex!
setindex!(x::ScryptElement, y::SalsaBlock, i) = setindex!(x.data, y, i)

import Base.view
view(x::ScryptElement, i) = view(x.data, i)

import Base.length
length(x::ScryptElement) = length(x.data)

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
    y.data[2:end] = [x.data[i] |> prepare for i ∈ 1:length(x.data) - 1]
    y.data[1] = x.data[end] |> prepare
    return y
end

function restore!(dest::ScryptElement, x::ScryptElement)
    dest.data[1:end - 1] = [x.data[i] |> restore for i ∈ 2:length(x.data)]
    dest.data[end] = x.data[1] |> restore
end
