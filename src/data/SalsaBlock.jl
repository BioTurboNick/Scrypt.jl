primitive type SalsaBlock 512 end

SalsaBlock() = Vector(reinterpret(SalsaBlock, zeros(UInt128, 4)))[1] # better way?

SalsaBlock(x::AbstractVector) = reinterpret(SalsaBlock, x)
