import SIMD.Intrinsics: argtoptr, d
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
    mod = """
            declare void @llvm.prefetch(i8*, i32, i32, i32)

            define void @entry($(d[Ptr])) #0 {
            top:
                %ptr = $argtoptr $(d[Ptr]) %0 to i8*
                call void @llvm.prefetch(i8* %ptr, i32 $ReadOrWrite, i32 $Locality, i32 1)
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
