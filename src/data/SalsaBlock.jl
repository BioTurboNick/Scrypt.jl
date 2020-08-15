primitive type SalsaBlock 512 end

import Base.zero
zero(::Type{SalsaBlock}) = reinterpret(SalsaBlock, zeros(UInt128, 4))[1]

SalsaBlock() = reinterpret(SalsaBlock, zeros(UInt128, 4))
SalsaBlock(row1::SalsaRow, row2::SalsaRow, row3::SalsaRow, row3::SalsaRow) = Vector(reinterpret(SalsaBlock, [row1, row2, row3, row4]))[1]

primitive type SalsaRow 128 end

SalsaRow() = Vector(reinterpret(SalsaBlock, zero(UInt128))[1]
SalsaRow(items::UInt32, item2::UInt32, item3::UInt32, item4::UInt32) = Vector(reinterpret(SalsaRow, [item1, item2, item3, item4]))[1]



getindex(x::SalsaBlock, i) = reinterpret(UInt128)


struct SalsaBlock1
    row1::SalsaRow
    row2::SalsaRow
    row3::SalsaRow
    row4::SalsaRow
end

