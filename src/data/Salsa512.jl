primitive type Salsa512 512 end




Salsa512(x::Vector{UInt128}) = reinterpret(Salsa512, x) |> first

import Base.zero
zero(::Type{Salsa512}) = zeros(UInt128, 4) |> Salsa512
