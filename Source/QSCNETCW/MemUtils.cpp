#include "MemUtils.h"

namespace QSCNETCW
{
    bool MemUtils::FlushCacheLine(IntPtr address)
    {
        bool res;

        res = false;

        if (address != IntPtr::Zero)
        {
            qsc_memutils_flush_cache_line(address.ToPointer());
            res = true;
        }

        return res;
    }

    bool MemUtils::PrefetchL1(array<Byte>^ data, size_t length)
    {
        bool res;

        res = false;

        if (data != nullptr)
        {
            if (data->LongLength >= static_cast<long>(length))
            {
                pin_ptr<Byte> pinned = &data[0];
                qsc_memutils_prefetch_l1(pinned, length);
                res = true;
            }
        }

        return res;
    }

    bool MemUtils::PrefetchL2(array<Byte>^ data, size_t length)
    {
        bool res;

        res = false;

        if (data != nullptr)
        {
            if (data->LongLength >= static_cast<long>(length))
            {
                pin_ptr<Byte> pinned = &data[0];
                qsc_memutils_prefetch_l2(pinned, length);
                res = true;
            }
        }

        return res;
    }

    bool MemUtils::PrefetchL3(array<Byte>^ data, size_t length)
    {
        bool res;

        res = false;

        if (data != nullptr)
        {
            if (data->LongLength >= static_cast<long>(length))
            {
                pin_ptr<Byte> pinned = &data[0];
                qsc_memutils_prefetch_l3(pinned, length);
                res = true;
            }
        }

        return res;
    }

    IntPtr MemUtils::Malloc(size_t length)
    {
        void* ptr = qsc_memutils_malloc(length);
        return IntPtr(ptr);
    }

    IntPtr MemUtils::Realloc(IntPtr blockPtr, size_t length)
    {
        void* ptr = qsc_memutils_realloc(blockPtr.ToPointer(), length);
        return IntPtr(ptr);
    }

    void MemUtils::AllocFree(IntPtr blockPtr)
    {
        qsc_memutils_alloc_free(blockPtr.ToPointer());
    }

    IntPtr MemUtils::AlignedAlloc(int32_t alignment, size_t length)
    {
        void* ptr = qsc_memutils_aligned_alloc(alignment, length);
        return IntPtr(ptr);
    }

    IntPtr MemUtils::AlignedRealloc(IntPtr blockPtr, size_t length)
    {
        void* ptr = qsc_memutils_aligned_realloc(blockPtr.ToPointer(), length);
        return IntPtr(ptr);
    }

    void MemUtils::AlignedFree(IntPtr blockPtr)
    {
        qsc_memutils_aligned_free(blockPtr.ToPointer());
    }

    bool MemUtils::Clear(array<Byte>^ output, size_t length)
    {
        bool res;

        res = false;

        if (output != nullptr)
        {
            if (output->LongLength >= static_cast<long>(length))
            {
                pin_ptr<Byte> pinnedOut = &output[0];
                qsc_memutils_clear(pinnedOut, length);
                res = true;
            }
        }

        return res;
    }

    bool MemUtils::ArrayUniform(array<Byte>^ data, size_t length)
    {
        bool res;

        res = false;

        if (data != nullptr)
        {
            if (data->LongLength >= static_cast<long>(length))
            {
                pin_ptr<Byte> pinnedData = &data[0];
                bool uniform = qsc_memutils_array_uniform(pinnedData, length);

                if (uniform == true)
                {
                    res = true;
                }
            }
        }

        return res;
    }

    bool MemUtils::AreEqual(array<Byte>^ a, array<Byte>^ b, size_t length)
    {
        bool res;

        res = false;

        if (a != nullptr && b != nullptr)
        {
            if (a->LongLength >= static_cast<long>(length) &&
                b->LongLength >= static_cast<long>(length))
            {
                pin_ptr<Byte> pinnedA = &a[0];
                pin_ptr<Byte> pinnedB = &b[0];

                if (qsc_memutils_are_equal(pinnedA, pinnedB, length) == true)
                {
                    res = true;
                }
            }
        }

        return res;
    }

    bool MemUtils::AreEqual128(array<Byte>^ a, array<Byte>^ b)
    {
        bool res;

        res = false;

        if (a != nullptr && b != nullptr)
        {
            if (a->LongLength >= 16 && b->LongLength >= 16)
            {
                pin_ptr<Byte> pinnedA = &a[0];
                pin_ptr<Byte> pinnedB = &b[0];

                if (qsc_memutils_are_equal_128(pinnedA, pinnedB) == true)
                {
                    res = true;
                }
            }
        }

        return res;
    }

    bool MemUtils::AreEqual256(array<Byte>^ a, array<Byte>^ b)
    {
        bool res;

        res = false;

        if (a != nullptr && b != nullptr)
        {
            if (a->LongLength >= 32 && b->LongLength >= 32)
            {
                pin_ptr<Byte> pinnedA = &a[0];
                pin_ptr<Byte> pinnedB = &b[0];

                if (qsc_memutils_are_equal_256(pinnedA, pinnedB) == true)
                {
                    res = true;
                }
            }
        }

        return res;
    }

    bool MemUtils::AreEqual512(array<Byte>^ a, array<Byte>^ b)
    {
        bool res;

        res = false;

        if (a != nullptr && b != nullptr)
        {
            if (a->LongLength >= 64 && b->LongLength >= 64)
            {
                pin_ptr<Byte> pinnedA = &a[0];
                pin_ptr<Byte> pinnedB = &b[0];

                if (qsc_memutils_are_equal_512(pinnedA, pinnedB) == true)
                {
                    res = true;
                }
            }
        }

        return res;
    }

    bool MemUtils::Copy(array<Byte>^ output, array<Byte>^ input, size_t length)
    {
        bool res;

        res = false;

        if (output != nullptr && input != nullptr)
        {
            if (output->LongLength >= static_cast<long>(length) &&
                input->LongLength >= static_cast<long>(length))
            {
                pin_ptr<Byte> pinnedOut = &output[0];
                pin_ptr<Byte> pinnedIn = &input[0];

                qsc_memutils_copy(pinnedOut, pinnedIn, length);
                res = true;
            }
        }

        return res;
    }

    bool MemUtils::Move(array<Byte>^ output, array<Byte>^ input, size_t length)
    {
        bool res;

        res = false;

        if (output != nullptr && input != nullptr)
        {
            if (output->LongLength >= static_cast<long>(length) &&
                input->LongLength >= static_cast<long>(length))
            {
                pin_ptr<Byte> pinnedOut = &output[0];
                pin_ptr<Byte> pinnedIn = &input[0];

                qsc_memutils_move(pinnedOut, pinnedIn, length);
                res = true;
            }
        }

        return res;
    }

    bool MemUtils::GreaterThanBE128(array<Byte>^ a, array<Byte>^ b)
    {
        bool res;

        res = false;

        if (a != nullptr && b != nullptr)
        {
            if (a->LongLength >= 16 && b->LongLength >= 16)
            {
                pin_ptr<Byte> pinnedA = &a[0];
                pin_ptr<Byte> pinnedB = &b[0];

                if (qsc_memutils_greater_than_be128(pinnedA, pinnedB) == true)
                {
                    res = true;
                }
            }
        }

        return res;
    }

    bool MemUtils::GreaterThanBE256(array<Byte>^ a, array<Byte>^ b)
    {
        bool res;

        res = false;

        if (a != nullptr && b != nullptr)
        {
            if (a->LongLength >= 32 && b->LongLength >= 32)
            {
                pin_ptr<Byte> pinnedA = &a[0];
                pin_ptr<Byte> pinnedB = &b[0];

                if (qsc_memutils_greater_than_be256(pinnedA, pinnedB) == true)
                {
                    res = true;
                }
            }
        }

        return res;
    }

    bool MemUtils::GreaterThanBE512(array<Byte>^ a, array<Byte>^ b)
    {
        bool res;

        res = false;

        if (a != nullptr && b != nullptr)
        {
            if (a->LongLength >= 64 && b->LongLength >= 64)
            {
                pin_ptr<Byte> pinnedA = &a[0];
                pin_ptr<Byte> pinnedB = &b[0];

                if (qsc_memutils_greater_than_be512(pinnedA, pinnedB) == true)
                {
                    res = true;
                }
            }
        }

        return res;
    }

    bool MemUtils::GreaterThanLE128(array<Byte>^ a, array<Byte>^ b)
    {
        bool res;

        res = false;

        if (a != nullptr && b != nullptr)
        {
            if (a->LongLength >= 16 && b->LongLength >= 16)
            {
                pin_ptr<Byte> pinnedA = &a[0];
                pin_ptr<Byte> pinnedB = &b[0];

                if (qsc_memutils_greater_than_le128(pinnedA, pinnedB) == true)
                {
                    res = true;
                }
            }
        }

        return res;
    }

    bool MemUtils::GreaterThanLE256(array<Byte>^ a, array<Byte>^ b)
    {
        bool res;

        res = false;

        if (a != nullptr && b != nullptr)
        {
            if (a->LongLength >= 32 && b->LongLength >= 32)
            {
                pin_ptr<Byte> pinnedA = &a[0];
                pin_ptr<Byte> pinnedB = &b[0];

                if (qsc_memutils_greater_than_le256(pinnedA, pinnedB) == true)
                {
                    res = true;
                }
            }
        }

        return res;
    }

    bool MemUtils::GreaterThanLE512(array<Byte>^ a, array<Byte>^ b)
    {
        bool res;

        res = false;

        if (a != nullptr && b != nullptr)
        {
            if (a->LongLength >= 64 && b->LongLength >= 64)
            {
                pin_ptr<Byte> pinnedA = &a[0];
                pin_ptr<Byte> pinnedB = &b[0];

                if (qsc_memutils_greater_than_le512(pinnedA, pinnedB) == true)
                {
                    res = true;
                }
            }
        }

        return res;
    }

    bool MemUtils::SecureErase(array<Byte>^ block, size_t length)
    {
        bool res;

        res = false;

        if (block != nullptr)
        {
            if (block->LongLength >= static_cast<long>(length))
            {
                pin_ptr<Byte> pinned = &block[0];
                qsc_memutils_secure_erase(pinned, length);
                res = true;
            }
        }

        return res;
    }

    bool MemUtils::SecureFree(IntPtr blockPtr, size_t length)
    {
        bool res;

        res = false;

        if (blockPtr != IntPtr::Zero)
        {
            qsc_memutils_secure_free(blockPtr.ToPointer(), length);
            res = true;
        }

        return res;
    }

    IntPtr MemUtils::SecureMalloc(size_t length)
    {
        void* ptr = qsc_memutils_secure_malloc(length);
        return IntPtr(ptr);
    }

    bool MemUtils::SetValue(array<Byte>^ output, size_t length, Byte value)
    {
        bool res;

        res = false;

        if (output != nullptr)
        {
            if (output->LongLength >= static_cast<long>(length))
            {
                pin_ptr<Byte> pinned = &output[0];
                qsc_memutils_set_value(pinned, length, value);
                res = true;
            }
        }

        return res;
    }

    bool MemUtils::Xor(array<Byte>^ output, array<Byte>^ input, size_t length)
    {
        bool res;

        res = false;

        if (output != nullptr && input != nullptr)
        {
            if (output->LongLength >= static_cast<long>(length) &&
                input->LongLength >= static_cast<long>(length))
            {
                pin_ptr<Byte> pinnedOut = &output[0];
                pin_ptr<Byte> pinnedIn = &input[0];

                qsc_memutils_xor(pinnedOut, pinnedIn, length);
                res = true;
            }
        }

        return res;
    }

    bool MemUtils::Xorv(array<Byte>^ output, Byte value, size_t length)
    {
        bool res;

        res = false;

        if (output != nullptr)
        {
            if (output->LongLength >= static_cast<long>(length))
            {
                pin_ptr<Byte> pinnedOut = &output[0];
                qsc_memutils_xorv(pinnedOut, value, length);
                res = true;
            }
        }

        return res;
    }

    bool MemUtils::Zeroed(array<Byte>^ data, size_t length)
    {
        bool res;

        res = false;

        if (data != nullptr)
        {
            if (data->LongLength >= static_cast<long>(length))
            {
                pin_ptr<Byte> pinnedData = &data[0];

                if (qsc_memutils_zeroed(pinnedData, length) == true)
                {
                    res = true;
                }
            }
        }

        return res;
    }
}
