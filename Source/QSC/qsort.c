#include "qsort.h"

static int32_t qsort_partition_u8(int8_t* arr, int32_t start, int32_t end)
{
    int32_t count;
    int32_t i;
    int32_t j;
    int32_t k;
    int32_t pindex;
    int8_t pivot;
    int8_t ntmp;

    pindex = -1;

    if (arr != NULL)
    {
        count = 0;
        pivot = arr[start];

        for (k = start + 1; k <= end; ++k)
        {
            if (arr[k] <= pivot)
            {
                ++count;
            }
        }

        pindex = start + count;
        ntmp = arr[pindex];
        arr[pindex] = arr[start];
        arr[start] = ntmp;

        i = start;
        j = end;

        while (i < pindex && j > pindex)
        {

            while (arr[i] <= pivot)
            {
                ++i;
            }

            while (arr[j] > pivot)
            {
                --j;
            }

            if (i < pindex && j > pindex)
            {
                ntmp = arr[i];
                arr[i] = arr[j];
                arr[j] = ntmp;
                ++i;
                --j;
            }
        }
    }

    return pindex;
}
 
static int32_t qsort_partition_u16(int16_t* arr, int32_t start, int32_t end)
{
    int32_t count;
    int32_t i;
    int32_t j;
    int32_t k;
    int32_t pindex;
    int16_t pivot;
    int16_t ntmp;

    pindex = -1;

    if (arr != NULL)
    {
        count = 0;
        pivot = arr[start];

        for (k = start + 1; k <= end; ++k)
        {
            if (arr[k] <= pivot)
            {
                ++count;
            }
        }

        pindex = start + count;
        ntmp = arr[pindex];
        arr[pindex] = arr[start];
        arr[start] = ntmp;

        i = start;
        j = end;

        while (i < pindex && j > pindex)
        {

            while (arr[i] <= pivot)
            {
                ++i;
            }

            while (arr[j] > pivot)
            {
                --j;
            }

            if (i < pindex && j > pindex)
            {
                ntmp = arr[i];
                arr[i] = arr[j];
                arr[j] = ntmp;
                ++i;
                --j;
            }
        }
    }

    return pindex;
}
 
static int32_t qsort_partition_u32(int32_t* arr, int32_t start, int32_t end)
{
    int32_t count;
    int32_t i;
    int32_t j;
    int32_t k;
    int32_t pindex;
    int32_t pivot;
    int32_t ntmp;

    pindex = -1;

    if (arr != NULL)
    {
        count = 0;
        pivot = arr[start];

        for (k = start + 1; k <= end; ++k)
        {
            if (arr[k] <= pivot)
            {
                ++count;
            }
        }

        pindex = start + count;
        ntmp = arr[pindex];
        arr[pindex] = arr[start];
        arr[start] = ntmp;

        i = start;
        j = end;

        while (i < pindex && j > pindex)
        {

            while (arr[i] <= pivot)
            {
                ++i;
            }

            while (arr[j] > pivot)
            {
                --j;
            }

            if (i < pindex && j > pindex)
            {
                ntmp = arr[i];
                arr[i] = arr[j];
                arr[j] = ntmp;
                ++i;
                --j;
            }
        }
    }

    return pindex;
}
 
static int64_t qsort_partition_u64(int64_t* arr, int64_t start, int64_t end)
{
    int64_t count;
    int64_t i;
    int64_t j;
    int64_t k;
    int64_t pindex;
    int64_t pivot;
    int64_t ntmp;
    pindex = -1;

    if (arr != NULL)
    {
        count = 0;
        pivot = arr[start];

        for (k = start + 1; k <= end; ++k)
        {
            if (arr[k] <= pivot)
            {
                ++count;
            }
        }

        pindex = start + count;
        ntmp = arr[pindex];
        arr[pindex] = arr[start];
        arr[start] = ntmp;

        i = start;
        j = end;

        while (i < pindex && j > pindex)
        {

            while (arr[i] <= pivot)
            {
                ++i;
            }

            while (arr[j] > pivot)
            {
                --j;
            }

            if (i < pindex && j > pindex)
            {
                ntmp = arr[i];
                arr[i] = arr[j];
                arr[j] = ntmp;
                ++i;
                --j;
            }
        }
    }

    return pindex;
}
  
void qsc_qsort_sort_i8(int8_t* arr, int32_t start, int32_t end)
{
    QSC_ASSERT(arr != NULL);
    QSC_ASSERT(start >= 0);
    QSC_ASSERT(start <= end);

    if (arr != NULL && start >= 0 && start <= end)
    {
        while (start < end)
        {
            int8_t mid = start + (end - start) / (int8_t)2;

            /* median-of-three: sort arr[start], arr[mid], arr[end] */
            if (arr[mid] < arr[start])
            {
                int8_t t = arr[mid];
                arr[mid] = arr[start];
                arr[start] = t;
            }

            if (arr[end] < arr[start])
            {
                int8_t t = arr[end];
                arr[end] = arr[start];
                arr[start] = t;
            }

            if (arr[mid] < arr[end])
            {
                int8_t t = arr[mid];
                arr[mid] = arr[end];
                arr[end] = t;
            }

            int32_t p = qsort_partition_u8(arr, start, end);

            if (p - 1 - start < end - (p + 1))
            {
                qsc_qsort_sort_i8(arr, start, p - 1);
                start = p + 1;
            }
            else
            {
                qsc_qsort_sort_i8(arr, p + 1, end);
                end = p - 1;
            }
        }
    }
}
 
void qsc_qsort_sort_i16(int16_t* arr, int32_t start, int32_t end)
{
    QSC_ASSERT(arr != NULL);
    QSC_ASSERT(start >= 0);
    QSC_ASSERT(start <= end);

    if (arr != NULL && start >= 0 && start <= end)
    {
        while (start < end)
        {
            int16_t mid = start + (end - start) / 2;

            if (arr[mid] < arr[start])
            {
                int16_t t = arr[mid];
                arr[mid] = arr[start];
                arr[start] = t;
            }

            if (arr[end] < arr[start])
            {
                int16_t t = arr[end];
                arr[end] = arr[start];
                arr[start] = t;
            }

            if (arr[mid] < arr[end])
            {
                int16_t t = arr[mid];
                arr[mid] = arr[end];
                arr[end] = t;
            }

            int32_t p = qsort_partition_u16(arr, start, end);

            if (p - 1 - start < end - (p + 1))
            {
                qsc_qsort_sort_i16(arr, start, p - 1);
                start = p + 1;
            }
            else
            {
                qsc_qsort_sort_i16(arr, p + 1, end);
                end = p - 1;
            }
        }
    }
}

void qsc_qsort_sort_i32(int32_t* arr, int32_t start, int32_t end) 
{
    QSC_ASSERT(arr != NULL);
    QSC_ASSERT(start >= 0);
    QSC_ASSERT(start <= end);

    if (arr != NULL && start >= 0 && start <= end)
    {
        while (start < end)
        {
            int32_t mid = start + (end - start) / 2;

            if (arr[mid] < arr[start])
            {
                int32_t t = arr[mid];
                arr[mid] = arr[start];
                arr[start] = t;
            }

            if (arr[end] < arr[start])
            {
                int32_t t = arr[end];
                arr[end] = arr[start];
                arr[start] = t;
            }

            if (arr[mid] < arr[end])
            {
                int32_t t = arr[mid];
                arr[mid] = arr[end];
                arr[end] = t;
            }

            int32_t p = qsort_partition_u32(arr, start, end);

            if (p - 1 - start < end - (p + 1))
            {
                qsc_qsort_sort_i32(arr, start, p - 1);
                start = p + 1;
            }
            else
            {
                qsc_qsort_sort_i32(arr, p + 1, end);
                end = p - 1;
            }
        }
    }
}

void qsc_qsort_sort_i64(int64_t* arr, int64_t start, int64_t end)
{
    QSC_ASSERT(arr != NULL);
    QSC_ASSERT(start >= 0);
    QSC_ASSERT(start <= end);

    if (arr != NULL && start >= 0 && start <= end)
    {
        while (start < end)
        {
            int64_t mid = start + (end - start) / 2;

            if (arr[mid] < arr[start])
            {
                int64_t t = arr[mid];
                arr[mid] = arr[start];
                arr[start] = t;
            }

            if (arr[end] < arr[start])
            {
                int64_t t = arr[end];
                arr[end] = arr[start];
                arr[start] = t;
            }

            if (arr[mid] < arr[end])
            {
                int64_t t = arr[mid];
                arr[mid] = arr[end];
                arr[end] = t;
            }

            int64_t p = qsort_partition_u64(arr, start, end);

            if (p - 1 - start < end - (p + 1))
            {
                qsc_qsort_sort_i64(arr, start, p - 1);
                start = p + 1;
            }
            else
            {
                qsc_qsort_sort_i64(arr, p + 1, end);
                end = p - 1;
            }
        }
    }
}
