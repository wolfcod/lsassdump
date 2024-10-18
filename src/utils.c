#include <stdint.h>

/** return the number of characters in _Source or _MaxCount if exceeds */
size_t __cdecl nocrt_wcsnlen(
    _In_reads_or_z_(_MaxCount) wchar_t const* _Source,
    _In_                       size_t         _MaxCount
)
{
    size_t size = 0;
    if (_Source != NULL)
    {
        const wchar_t* tmp = (const wchar_t*)_Source;

        while (*tmp != 0 && size < _MaxCount)
        {
            size++;
            tmp++;
        }
    }

    return size;
}

size_t __cdecl nocrt_wcslen(const wchar_t * _Source)
{
    size_t size = 0;
    if (_Source != NULL)
    {
        for (; *_Source != 0; _Source++, size++);
    }

    return size;
}

#define isupper(c) (c >= L'A' && c<= L'Z')

wchar_t __cdecl nocrt_towlower(wchar_t c)
{
    if (isupper(c))
        return c - L'A' + 'a';
    return c;
}

/** compare _String1 and _String2 in lowercase */
int __cdecl nocrt_wcsicmp(
    _In_z_ wchar_t const* _String1,
    _In_z_ wchar_t const* _String2
)
{
    if (_String1 == _String2)
        return 0;

    if (nocrt_wcslen(_String1) != nocrt_wcslen(_String2))
        return -1;

    const wchar_t* a = (const wchar_t*)_String1;
    const wchar_t* b = (const wchar_t*)_String2;

    while (*a != 0 && *b != 0)
    {
        if (nocrt_towlower(*a) != nocrt_towlower(*b))
            return -1;
        a++; b++;
    }

    return 0;
}

