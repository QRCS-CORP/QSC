#include "qsort.h"

static int32_t qsort_partition_u8(int8_t* arr, int32_t start, int32_t end)
{
    int32_t count;
    int32_t i;
    int32_t j;
    int32_t pindex;
    int8_t pivot;
    int8_t ntmp;

    count = 0;
    pivot = arr[start];

    for (int32_t i = start + 1; i <= end; ++i) 
    {
        if (arr[i] <= pivot)
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
 
    return pindex;
}
 
static int32_t qsort_partition_u16(int16_t* arr, int32_t start, int32_t end)
{
    int32_t count;
    int32_t i;
    int32_t j;
    int32_t pindex;
    int16_t pivot;
    int16_t ntmp;

    count = 0;
    pivot = arr[start];

    for (int32_t i = start + 1; i <= end; ++i) 
    {
        if (arr[i] <= pivot)
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
 
    return pindex;
}
 
static int32_t qsort_partition_u32(int32_t* arr, int32_t start, int32_t end)
{
    int32_t count;
    int32_t i;
    int32_t j;
    int32_t pindex;
    int32_t pivot;
    int32_t ntmp;

    count = 0;
    pivot = arr[start];

    for (int32_t i = start + 1; i <= end; ++i) 
    {
        if (arr[i] <= pivot)
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
 
    return pindex;
}
 
static int64_t qsort_partition_u64(int64_t* arr, int64_t start, int64_t end)
{
    int64_t count;
    int64_t i;
    int64_t j;
    int64_t pindex;
    int64_t pivot;
    int64_t ntmp;

    count = 0;
    pivot = arr[start];

    for (int64_t i = start + 1; i <= end; ++i) 
    {
        if (arr[i] <= pivot)
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
 
    return pindex;
}
  
void qsc_qsort_sort_i8(int8_t* arr8, int32_t start, int32_t end)
{
    assert(arr8 != NULL);

    int16_t p;

    if (start <= end)
    {
        p = qsort_partition_u8(arr8, start, end);
        qsc_qsort_sort_i8(arr8, start, p - 1);
        qsc_qsort_sort_i8(arr8, p + 1, end);
    }
}
 
void qsc_qsort_sort_i16(int16_t* arr16, int32_t start, int32_t end)
{
    assert(arr16 != NULL);

    int16_t p;

    if (start <= end)
    {
        p = qsort_partition_u16(arr16, start, end);
        qsc_qsort_sort_i16(arr16, start, p - 1);
        qsc_qsort_sort_i16(arr16, p + 1, end);
    }
}
 
void qsc_qsort_sort_i32(int32_t* arr32, int32_t start, int32_t end)
{
    assert(arr32 != NULL);

    int32_t p;

    if (start <= end)
    {
        p = qsort_partition_u32(arr32, start, end);
        qsc_qsort_sort_i32(arr32, start, p - 1);
        qsc_qsort_sort_i32(arr32, p + 1, end);
    }
}
 
void qsc_qsort_sort_i64(int64_t* arr64, int64_t start, int64_t end)
{
    assert(arr64 != NULL);

    int64_t p;

    if (start <= end)
    {
        p = qsort_partition_u64(arr64, start, end);
        qsc_qsort_sort_i64(arr64, start, p - 1);
        qsc_qsort_sort_i64(arr64, p + 1, end);
    }
}
