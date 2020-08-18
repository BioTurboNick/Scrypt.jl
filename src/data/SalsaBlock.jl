"""
    SalsaBlock

The basic element of the scrypt algorithm. A 512-bit (64-byte) chunk of data
that is manipulated by the inner Salsa20/8 operations as a 4×4 matrix of
UInt32 values.
"""
primitive type SalsaBlock 512 end

SalsaBlock(x::AbstractVector) = reinterpret(SalsaBlock, x) |> first
SalsaBlock(x::MMatrix{4,4}) = reinterpret(SalsaBlock, reshape(x, 16)) |> first

ascolumns(x::SalsaBlock) = reinterpret(UInt128, [x])

asintegers(x::SalsaBlock) = reinterpret(UInt32, [x])

copystatic(x::SalsaBlock) = x |> asintegers |> MMatrix{4,4}

const SALSA_BLOCK_REORDER_INDEXES = [13;  2;  7; 12;  1;  6; 11; 16;  5; 10; 15;  4;  9; 14;  3;  8]
const SALSA_BLOCK_RESTORE_INDEXES = [ 5;  2; 15; 12;  9;  6;  3; 16; 13; 10;  7;  4;  1; 14; 11;  8]

"""
    prepare(x::SalsaBlock)
    restore(x::SalsaBlock)

The inner Salsa20/8 operations operate on diagonals. To simplify these
operations, we re-arrange each block so that the diagonals are placed in
columns. The data are restored to their original positions by restore().
"""
prepare(x::SalsaBlock) = @views asintegers(x)[SALSA_BLOCK_REORDER_INDEXES] |> SalsaBlock
restore(x::SalsaBlock) = @views asintegers(x)[SALSA_BLOCK_RESTORE_INDEXES] |> SalsaBlock

import Base.zero
zero(::Type{SalsaBlock}) = zeros(UInt128, 4)|> SalsaBlock
