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
    blocks::Vector{SalsaBlock}
    
    function ScryptElement(r::Int)
        data = Vector{Salsa512}(undef, 2r)
        ScryptElement(r, data)
    end
    function ScryptElement(r::Int, x::AbstractVector{Salsa512})
        length(x) == 2r || ArgumentError("x must be of length 2r")
        new{typeof(x)}(x, r, @views [SalsaBlock(x[i:i]) for i ∈ 1:length(x)])
    end
end

function swap!(x::ScryptElement, y::ScryptElement) 
    x.data, y.data = y.data, x.data
    x.blocks, y.blocks = y.blocks, x.blocks
    ()
end

import Base.getindex
getindex(x::ScryptElement, i) = x.blocks[i]

import Base.setindex!
function setindex!(x::ScryptElement, y::SalsaBlock, i)
    x.data[i] = asblock(y).data[1]
    x.blocks[i] = @views SalsaBlock(x.data[i:i])
end
function setindex!(x::ScryptElement, y::AbstractVector{SalsaBlock{T}}, r) where {T}
    x.data[r] .= (asblock(yi).data[1] for yi ∈ y)
    y.blocks[r] .= @views (SalsaBlock(y.data[i:i]) for i ∈ r)
end

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
    y.data[2:end] = x.data[1:end - 1]
    y.data[1] = x.data[end]
    prepare!.(y.blocks)
    return y
end

function restore!(dest::ScryptElement, x::ScryptElement)
    restore!.(x.blocks)
    dest.data[end] = x.data[1]
    dest.data[1:end - 1] = x.data[2:end]
    ()
end
