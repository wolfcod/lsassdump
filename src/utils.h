#pragma once

#ifdef _DEBUG
#define WCSNLEN wcsnlen
#define _WCSICMP _wcsicmp
#else
#ifdef __cplusplus
extern "C"
#endif
size_t __cdecl nocrt_wcsnlen(
    _In_reads_or_z_(_MaxCount) wchar_t const* _Source,
    _In_                       size_t         _MaxCount
);

#ifdef __cplusplus
extern "C"
#endif
int __cdecl nocrt_wcsicmp(
    _In_z_ wchar_t const* _String1,
    _In_z_ wchar_t const* _String2
);

#define WCSNLEN nocrt_wcsnlen
#define _WCSICMP nocrt_wcsicmp

#endif
