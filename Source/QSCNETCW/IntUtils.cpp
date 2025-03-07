#include "IntUtils.h"
#include <vector>

namespace QSCNETCW
{
    using namespace System::Runtime::InteropServices;

    bool IntUtils::AreEqual8(array<Byte>^ a, array<Byte>^ b, size_t length)
    {
        bool res = false;

        if (a != nullptr && b != nullptr)
        {
            if (a->LongLength >= static_cast<long>(length) && b->LongLength >= static_cast<long>(length))
            {
                pin_ptr<Byte> pinnedA = &a[0];
                pin_ptr<Byte> pinnedB = &b[0];

                if (qsc_intutils_are_equal8(pinnedA, pinnedB, length))
                {
                    res = true;
                }
            }
        }

        return res;
    }

    UInt16 IntUtils::BE8To16(array<Byte>^ input)
    {
        UInt16 val = 0;

        if (input != nullptr && input->LongLength >= 2)
        {
            pin_ptr<Byte> pinned = &input[0];
            val = static_cast<UInt16>(qsc_intutils_be8to16(pinned));
        }

        return val;
    }

    UInt32 IntUtils::BE8To32(array<Byte>^ input)
    {
        UInt32 val = 0;

        if (input != nullptr && input->LongLength >= 4)
        {
            pin_ptr<Byte> pinned = &input[0];
            val = qsc_intutils_be8to32(pinned);
        }

        return val;
    }

    UInt64 IntUtils::BE8To64(array<Byte>^ input)
    {
        UInt64 val = 0;

        if (input != nullptr && input->LongLength >= 8)
        {
            pin_ptr<Byte> pinned = &input[0];
            val = qsc_intutils_be8to64(pinned);
        }

        return val;
    }

    bool IntUtils::BE16To8(array<Byte>^ output, UInt16 value)
    {
        bool res = false;

        if (output != nullptr && output->LongLength >= 2)
        {
            pin_ptr<Byte> pinned = &output[0];
            qsc_intutils_be16to8(pinned, value);
            res = true;
        }

        return res;
    }

    bool IntUtils::BE32To8(array<Byte>^ output, UInt32 value)
    {
        bool res = false;

        if (output != nullptr && output->LongLength >= 4)
        {
            pin_ptr<Byte> pinned = &output[0];
            qsc_intutils_be32to8(pinned, value);
            res = true;
        }

        return res;
    }

    bool IntUtils::BE64To8(array<Byte>^ output, UInt64 value)
    {
        bool res = false;

        if (output != nullptr && output->LongLength >= 8)
        {
            pin_ptr<Byte> pinned = &output[0];
            qsc_intutils_be64to8(pinned, value);
            res = true;
        }

        return res;
    }

    bool IntUtils::BE8Increment(array<Byte>^ output, size_t length)
    {
        bool res = false;

        if (output != nullptr && output->LongLength >= static_cast<long>(length))
        {
            pin_ptr<Byte> pinned = &output[0];
            qsc_intutils_be8increment(pinned, length);
            res = true;
        }

        return res;
    }

    size_t IntUtils::BitReverse(size_t x, UInt32 bits)
    {
        size_t val = 0;

        val = qsc_intutils_bit_reverse(x, bits);
        
        return val;
    }

    UInt64 IntUtils::BitReverseU64(UInt64 x)
    {
        UInt64 val = 0;
        
        val = qsc_intutils_bit_reverse_u64(x);
        
        return val;
    }

    UInt32 IntUtils::BitReverseU32(UInt32 x)
    {
        UInt32 val = 0;
        
        val = qsc_intutils_bit_reverse_u32(x);
        
        return val;
    }

    UInt16 IntUtils::BitReverseU16(UInt16 x)
    {
        UInt16 val = 0;
        
        val = qsc_intutils_bit_reverse_u16(x);
        
        return val;
    }

    double IntUtils::CalculateAbs(double a)
    {
        double val = 0.0;
        
        val = qsc_intutils_calculate_abs(a);
        
        return val;
    }

    double IntUtils::CalculateExp(double x)
    {
        double val = 0.0;
        
        val = qsc_intutils_calculate_exp(x);
        
        return val;
    }

    double IntUtils::CalculateFabs(double x)
    {
        double val = 0.0;
        
        val = qsc_intutils_calculate_fabs(x);
        
        return val;
    }

    double IntUtils::CalculateLog(double x)
    {
        double val = 0.0;
        
        val = qsc_intutils_calculate_log(x);
        
        return val;
    }

    double IntUtils::CalculateSqrt(double x)
    {
        double val = 0.0;
        
        val = qsc_intutils_calculate_sqrt(x);
        
        return val;
    }

    bool IntUtils::Clear8(array<Byte>^ a, size_t count)
    {
        bool res = false;

        if (a != nullptr && a->LongLength >= static_cast<long>(count))
        {
            pin_ptr<Byte> pinned = &a[0];
            qsc_intutils_clear8(pinned, count);
            res = true;
        }

        return res;
    }

    bool IntUtils::Clear16(array<UInt16>^ a, size_t count)
    {
        bool res = false;

        if (a != nullptr && a->LongLength >= static_cast<long>(count))
        {
            pin_ptr<UInt16> pinned = &a[0];
            qsc_intutils_clear16(pinned, count);
            res = true;
        }

        return res;
    }

    bool IntUtils::Clear32(array<UInt32>^ a, size_t count)
    {
        bool res = false;

        if (a != nullptr && a->LongLength >= static_cast<long>(count))
        {
            pin_ptr<UInt32> pinned = &a[0];
            qsc_intutils_clear32(pinned, count);
            res = true;
        }

        return res;
    }

    bool IntUtils::Clear64(array<UInt64>^ a, size_t count)
    {
        bool res = false;

        if (a != nullptr && a->LongLength >= static_cast<long>(count))
        {
            pin_ptr<UInt64> pinned = &a[0];
            qsc_intutils_clear64(pinned, count);
            res = true;
        }

        return res;
    }

    bool IntUtils::Cmov(array<Byte>^ dest, array<Byte>^ source, size_t length, Byte cond)
    {
        bool res = false;

        if (dest != nullptr && source != nullptr)
        {
            if (dest->LongLength >= static_cast<long>(length) && source->LongLength >= static_cast<long>(length))
            {
                pin_ptr<Byte> pinnedDest = &dest[0];
                pin_ptr<Byte> pinnedSrc = &source[0];
                qsc_intutils_cmov(pinnedDest, pinnedSrc, length, cond);
                res = true;
            }
        }

        return res;
    }

    size_t IntUtils::ExpandMask(size_t x)
    {
        size_t val = 0;
        
        val = qsc_intutils_expand_mask(x);
        
        return val;
    }

    bool IntUtils::IntsAreEqual(size_t x, size_t y)
    {
        bool res = false;
        
        if (qsc_intutils_are_equal(x, y))
        {
            res = true;
        }
        
        return res;
    }

    bool IntUtils::IsGte(size_t x, size_t y)
    {
        bool res = false;
        
        if (qsc_intutils_is_gte(x, y))
        {
            res = true;
        }
        
        return res;
    }

    bool IntUtils::HexToBin(String^ hexstr, array<Byte>^ output, size_t outlen)
    {
        bool res = false;

        if (hexstr != nullptr && output != nullptr)
        {
            if (output->LongLength >= static_cast<long>(outlen))
            {
                IntPtr phexstr = Marshal::StringToHGlobalAnsi(hexstr);
                pin_ptr<Byte> pinnedOut = &output[0];
                qsc_intutils_hex_to_bin(static_cast<char*>(phexstr.ToPointer()), pinnedOut, outlen);
                Marshal::FreeHGlobal(phexstr);
                res = true;
            }
        }

        return res;
    }

    bool IntUtils::BinToHex(array<Byte>^ input, String^% hexstr)
    {
        bool res = false;

        hexstr = nullptr;

        if (input != nullptr)
        {
            pin_ptr<Byte> pinnedIn = &input[0];
            size_t inplen = static_cast<size_t>(input->LongLength);
            std::vector<char> buffer(inplen * 2 + 1, '\0');
            qsc_intutils_bin_to_hex(pinnedIn, buffer.data(), inplen);
            hexstr = gcnew String(buffer.data());
            res = true;
        }

        return res;
    }

    bool IntUtils::LE8Increment(array<Byte>^ output, size_t length)
    {
        bool res = false;

        if (output != nullptr && output->LongLength >= static_cast<long>(length))
        {
            pin_ptr<Byte> pinned = &output[0];
            qsc_intutils_le8increment(pinned, length);
            res = true;
        }

        return res;
    }

    bool IntUtils::Bswap32(array<UInt32>^ dest, array<UInt32>^ source, size_t length)
    {
#if defined(QSC_SYSTEM_HAS_AVX)
        bool res = false;

        if (dest != nullptr && source != nullptr)
        {
            if (dest->LongLength >= static_cast<long>(length) && source->LongLength >= static_cast<long>(length))
            {
                pin_ptr<UInt32> pinnedD = &dest[0];
                pin_ptr<UInt32> pinnedS = &source[0];
                qsc_intutils_bswap32(pinnedD, pinnedS, length);
                res = true;
            }
        }

        return res;
#else
        return false;
#endif
    }

    bool IntUtils::Bswap64(array<UInt64>^ dest, array<UInt64>^ source, size_t length)
    {
#if defined(QSC_SYSTEM_HAS_AVX)
        bool res = false;

        if (dest != nullptr && source != nullptr)
        {
            if (dest->LongLength >= static_cast<long>(length) && source->LongLength >= static_cast<long>(length))
            {
                pin_ptr<UInt64> pinnedD = &dest[0];
                pin_ptr<UInt64> pinnedS = &source[0];
                qsc_intutils_bswap64(pinnedD, pinnedS, length);
                res = true;
            }
        }

        return res;
#else
        return false;
#endif
    }

    bool IntUtils::LeIncrementX128(IntPtr counterPtr)
    {
#if defined(QSC_SYSTEM_HAS_AVX)
        bool res = false;

        if (counterPtr != IntPtr::Zero)
        {
            __m128i* ptr = reinterpret_cast<__m128i*>(counterPtr.ToPointer());
            qsc_intutils_leincrement_x128(ptr);
            res = true;
        }

        return res;
#else
        return false;
#endif
    }

    bool IntUtils::LeIncrementX512(IntPtr counterPtr)
    {
#if defined(QSC_SYSTEM_HAS_AVX512)
        bool res = false;

        if (counterPtr != IntPtr::Zero)
        {
            __m512i* ptr = reinterpret_cast<__m512i*>(counterPtr.ToPointer());
            qsc_intutils_leincrement_x512(ptr);
            res = true;
        }

        return res;
#else
        return false;
#endif
    }

    bool IntUtils::ReverseBytesX128(IntPtr inputPtr, IntPtr outputPtr)
    {
#if defined(QSC_SYSTEM_HAS_AVX)
        bool res = false;

        if (inputPtr != IntPtr::Zero && outputPtr != IntPtr::Zero)
        {
            const __m128i* inp = reinterpret_cast<const __m128i*>(inputPtr.ToPointer());
            __m128i* outp = reinterpret_cast<__m128i*>(outputPtr.ToPointer());
            qsc_intutils_reverse_bytes_x128(inp, outp);
            res = true;
        }

        return res;
#else
        return false;
#endif
    }

    bool IntUtils::ReverseBytesX512(IntPtr inputPtr, IntPtr outputPtr)
    {
#if defined(QSC_SYSTEM_HAS_AVX512)
        bool res = false;

        if (inputPtr != IntPtr::Zero && outputPtr != IntPtr::Zero)
        {
            const __m512i* inp = reinterpret_cast<const __m512i*>(inputPtr.ToPointer());
            __m512i* outp = reinterpret_cast<__m512i*>(outputPtr.ToPointer());
            qsc_intutils_reverse_bytes_x512(inp, outp);
            res = true;
        }

        return res;
#else
        return false;
#endif
    }

    UInt16 IntUtils::LE8To16(array<Byte>^ input)
    {
        UInt16 val = 0;

        if (input != nullptr && input->LongLength >= 2)
        {
            pin_ptr<Byte> pinned = &input[0];
            val = static_cast<UInt16>(qsc_intutils_le8to16(pinned));
        }

        return val;
    }

    UInt32 IntUtils::LE8To32(array<Byte>^ input)
    {
        UInt32 val = 0;

        if (input != nullptr && input->LongLength >= 4)
        {
            pin_ptr<Byte> pinned = &input[0];
            val = qsc_intutils_le8to32(pinned);
        }

        return val;
    }

    UInt64 IntUtils::LE8To64(array<Byte>^ input)
    {
        UInt64 val = 0;

        if (input != nullptr && input->LongLength >= 8)
        {
            pin_ptr<Byte> pinned = &input[0];
            val = qsc_intutils_le8to64(pinned);
        }

        return val;
    }

    bool IntUtils::LE16To8(array<Byte>^ output, UInt16 value)
    {
        bool res = false;

        if (output != nullptr && output->LongLength >= 2)
        {
            pin_ptr<Byte> pinned = &output[0];
            qsc_intutils_le16to8(pinned, value);
            res = true;
        }

        return res;
    }

    bool IntUtils::LE32To8(array<Byte>^ output, UInt32 value)
    {
        bool res = false;

        if (output != nullptr && output->LongLength >= 4)
        {
            pin_ptr<Byte> pinned = &output[0];
            qsc_intutils_le32to8(pinned, value);
            res = true;
        }

        return res;
    }

    bool IntUtils::LE64To8(array<Byte>^ output, UInt64 value)
    {
        bool res = false;

        if (output != nullptr && output->LongLength >= 8)
        {
            pin_ptr<Byte> pinned = &output[0];
            qsc_intutils_le64to8(pinned, value);
            res = true;
        }

        return res;
    }

    size_t IntUtils::Max(size_t a, size_t b)
    {
        size_t val = 0;
        
        val = qsc_intutils_max(a, b);
        
        return val;
    }

    size_t IntUtils::Min(size_t a, size_t b)
    {
        size_t val = 0;
        
        val = qsc_intutils_min(a, b);
        
        return val;
    }

    UInt32 IntUtils::Popcount32(UInt32 v)
    {
        UInt32 val = 0;
        
        val = qsc_intutils_popcount32(v);
        
        return val;
    }

    UInt32 IntUtils::Rotl32(UInt32 value, size_t shift)
    {
        UInt32 val = 0;
        
        val = qsc_intutils_rotl32(value, shift);
        
        return val;
    }

    UInt64 IntUtils::Rotl64(UInt64 value, size_t shift)
    {
        UInt64 val = 0;
        
        val = qsc_intutils_rotl64(value, shift);
        
        return val;
    }

    UInt32 IntUtils::Rotr32(UInt32 value, size_t shift)
    {
        UInt32 val = 0;
        
        val = qsc_intutils_rotr32(value, shift);
        
        return val;
    }

    UInt64 IntUtils::Rotr64(UInt64 value, size_t shift)
    {
        UInt64 val = 0;
        
        val = qsc_intutils_rotr64(value, shift);
        
        return val;
    }

    int IntUtils::Verify(array<Byte>^ a, array<Byte>^ b, size_t length)
    {
        int result = -1;

        if (a != nullptr && b != nullptr)
        {
            if (a->LongLength >= static_cast<long>(length) && b->LongLength >= static_cast<long>(length))
            {
                pin_ptr<Byte> pinnedA = &a[0];
                pin_ptr<Byte> pinnedB = &b[0];
                result = qsc_intutils_verify(pinnedA, pinnedB, length);
            }
        }
        return result;
    }
}
