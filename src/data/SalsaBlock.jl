"""
    SalsaBlock

The basic element of the scrypt algorithm. A 512-bit (64-byte) chunk of data
that is manipulated by the inner Salsa20/8 operations as a 4×4 matrix of
UInt32 values. Contains a reference to its underlying data, which may be a
subarray.
"""
struct SalsaBlock{T <: AbstractVector}
    data::T

    function SalsaBlock(x::AbstractVector)
        length(x) * sizeof(eltype(x)) == sizeof(Salsa512) || ArgumentError("Must be 64 bytes.") |> throw
        new{typeof(x)}(x)
    end
    SalsaBlock(x::AbstractMatrix) = x |> vec |> SalsaBlock
end

ascolumns(x::SalsaBlock) = reinterpret(UInt128, x.data) |> SalsaBlock
asintegers(x::SalsaBlock) = reinterpret(UInt32, x.data) |> SalsaBlock
asblock(x::SalsaBlock) = reinterpret(Salsa512, x.data) |> SalsaBlock

import Base.getindex
getindex(x::SalsaBlock, i) = x.data[i]

import Base.setindex!
setindex!(x::SalsaBlock, y::UInt128, i) = setindex!((x |> ascolumns).data, y, i)
setindex!(x::SalsaBlock, y::UInt32, i) = setindex!((x |> asintegers).data, y, i)
setindex!(x::SalsaBlock, y::Salsa512, i) = setindex!((x |> asblock).data, y, i)


import Base.copyto!
copyto!(dest::SalsaBlock, src::AbstractVecOrMat) = reinterpret(eltype(src), dest.data) .= src |> vec

function xor!(x::SalsaBlock, y::SalsaBlock)
    xcols = x |> ascolumns
    xcols.data .= xcols.data .⊻ ascolumns(y).data
end

const SALSA_BLOCK_REORDER_INDEXES = [13;  2;  7; 12;  1;  6; 11; 16;  5; 10; 15;  4;  9; 14;  3;  8]
const SALSA_BLOCK_RESTORE_INDEXES = [ 5;  2; 15; 12;  9;  6;  3; 16; 13; 10;  7;  4;  1; 14; 11;  8]

"""
    prepare(x::SalsaBlock)
    restore(x::SalsaBlock)

The inner Salsa20/8 operations operate on diagonals. To simplify these
operations, we re-arrange each block so that the diagonals are placed in
columns. The data are restored to their original positions by restore().
"""
prepare!(x::SalsaBlock) = x.data[:] = reinterpret(Salsa512, asintegers(x)[SALSA_BLOCK_REORDER_INDEXES])
restore!(x::SalsaBlock) = x.data[:] = reinterpret(Salsa512, asintegers(x)[SALSA_BLOCK_RESTORE_INDEXES])

copystatic(x::SalsaBlock) = asintegers(x).data |> MMatrix{4,4}

