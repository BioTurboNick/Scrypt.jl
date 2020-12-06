"""
ReadOrWrite: 0 for read, 1 for write.
Function follows the LLVM definition
https://llvm.org/docs/LangRef.html#llvm-prefetch-intrinsic
such that
prefetch(ptr, Val(3), Val(0))
corresponds to prefetch0 on x86 (extreme locality)
Adapted from SIMDPirates.jl
"""
@generated function prefetch(ptr::Ptr{T}, ::Val{Locality}, ::Val{ReadOrWrite}) where {T, Locality, ReadOrWrite}
    if VERSION < v"1.6.0-DEV.674"
        prefetch_call_string = """%addr = inttoptr i$(8sizeof(Int)) %0 to i8*
        call void @llvm.prefetch(i8* %addr, i32 $ReadOrWrite, i32 $Locality, i32 1)
        ret void"""
        quote
            $(Expr(:meta, :inline))
            Base.llvmcall(
                ("declare void @llvm.prefetch(i8*, i32, i32, i32)",
                $prefetch_call_string), Cvoid, Tuple{Ptr{$T}}, ptr
            )
        end
    else
        mod = """
            declare void @llvm.prefetch(i8*, i32, i32, i32)

            define void @entry(i$(8sizeof(Int))) #0 {
            top:
                %addr = inttoptr i$(8sizeof(Int)) %0 to i8*
                call void @llvm.prefetch(i8* %addr, i32 $ReadOrWrite, i32 $Locality, i32 1)
                ret void
            }

            attributes #0 = { alwaysinline }
        """
        quote
            $(Expr(:meta, :inline))
            Base.llvmcall(
                ($mod, "entry"), Cvoid, Tuple{Ptr{$T}}, ptr
            )
        end
    end
end

function vprefetch(a::SIMD.FastContiguousArray{T,1}, i::Integer) where {T}
    GC.@preserve a begin
        ptr = @inbounds pointer(a, i)
        prefetch(ptr, Val{3}(), Val{0}())
    end
end

function vprefetchnt(a::SIMD.FastContiguousArray{T,1}, i::Integer) where {T}
    GC.@preserve a begin
        ptr = @inbounds pointer(a, i)
        prefetch(ptr, Val{0}(), Val{0}())
    end
end


if VERSION < v"1.6.0-DEV"
    import Base.stride
    import Base.strides

    function stride(a::Base.ReinterpretArray, i::Int)
        a.parent isa StridedArray || ArgumentError("Parent must be strided.") |> throw
        if i > ndims(a)
            return length(a)
        end
        s = 1
        for n = 1:(i-1)
            s *= size(a, n)
        end
        return s
    end

    function strides(a::Base.ReinterpretArray)
        a.parent isa StridedArray || ArgumentError("Parent must be strided.") |> throw
        Base.size_to_strides(1, size(a)...)
    end
end