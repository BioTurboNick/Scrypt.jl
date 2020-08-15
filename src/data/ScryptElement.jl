struct ScryptElement
    data::AbstractVector{UInt32}

    function ScryptElement(bytes)
        bytes % 64 == 0 || ArgumentError("Bytes must be a multiple of 64.") |> throw
        data = zeros(UInt32, Int(bytes / sizeof(UInt32)))
    end
end
