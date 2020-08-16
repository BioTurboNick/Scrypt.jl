primitive type SalsaBlock 512 end

import Base.zero
zero(::Type{SalsaBlock}) = reinterpret(SalsaBlock, zeros(UInt128, 4))[1]
