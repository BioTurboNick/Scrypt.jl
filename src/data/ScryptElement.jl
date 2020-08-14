struct ScryptElement
    data::AbstractVector

    ScryptElement(count) = new([SalsaBlock() for i ∈ 1:count])
end
