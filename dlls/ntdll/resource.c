/*
 * PE file resources
 *
 * Copyright 1995 Thomas Sandford
 * Copyright 1996 Martin von Loewis
 * Copyright 2003 Alexandre Julliard
 *
 * Based on the Win16 resource handling code in loader/resource.c
 * Copyright 1993 Robert J. Amstadt
 * Copyright 1995 Alexandre Julliard
 * Copyright 1997 Marcus Meissner
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

#include <stdarg.h>
#include <stdlib.h>
#include <sys/types.h>

#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "windef.h"
#include "winbase.h"
#include "winnt.h"
#include "winternl.h"
#include "ntdll_misc.h"
#include "wine/asm.h"
#include "wine/exception.h"
#include "winnls.h"
#include "wine/debug.h"

WINE_DEFAULT_DEBUG_CHANNEL(resource);

#define IS_INTRESOURCE(x)       (((ULONG_PTR)(x) >> 16) == 0)

/**********************************************************************
 *  is_data_file_module
 *
 * Check if a module handle is for a LOAD_LIBRARY_AS_DATAFILE module.
 */
static inline BOOL is_data_file_module( HMODULE hmod )
{
    return (ULONG_PTR)hmod & 1;
}


/**********************************************************************
 *  push_language
 *
 * push a language in the list of languages to try
 */
static inline int push_language( WORD *list, int pos, WORD lang )
{
    int i;
    for (i = 0; i < pos; i++) if (list[i] == lang) return pos;
    list[pos++] = lang;
    return pos;
}


/**********************************************************************
 *  find_first_entry
 *
 * Find the first suitable entry in a resource directory
 */
static const IMAGE_RESOURCE_DIRECTORY *find_first_entry( const IMAGE_RESOURCE_DIRECTORY *dir,
                                                         const void *root, int want_dir )
{
    const IMAGE_RESOURCE_DIRECTORY_ENTRY *entry = (const IMAGE_RESOURCE_DIRECTORY_ENTRY *)(dir + 1);
    int pos;

    for (pos = 0; pos < dir->NumberOfNamedEntries + dir->NumberOfIdEntries; pos++)
    {
        if (!entry[pos].DataIsDirectory == !want_dir)
            return (const IMAGE_RESOURCE_DIRECTORY *)((const char *)root + entry[pos].OffsetToDirectory);
    }
    return NULL;
}


/**********************************************************************
 *  find_entry_by_id
 *
 * Find an entry by id in a resource directory
 */
static const IMAGE_RESOURCE_DIRECTORY *find_entry_by_id( const IMAGE_RESOURCE_DIRECTORY *dir,
                                                         WORD id, const void *root, int want_dir )
{
    const IMAGE_RESOURCE_DIRECTORY_ENTRY *entry;
    int min, max, pos;

    entry = (const IMAGE_RESOURCE_DIRECTORY_ENTRY *)(dir + 1);
    min = dir->NumberOfNamedEntries;
    max = min + dir->NumberOfIdEntries - 1;
    while (min <= max)
    {
        pos = (min + max) / 2;
        if (entry[pos].Id == id)
        {
            if (!entry[pos].DataIsDirectory == !want_dir)
            {
                TRACE("root %p dir %p id %04x ret %p\n",
                      root, dir, id, (const char*)root + entry[pos].OffsetToDirectory);
                return (const IMAGE_RESOURCE_DIRECTORY *)((const char *)root + entry[pos].OffsetToDirectory);
            }
            break;
        }
        if (entry[pos].Id > id) max = pos - 1;
        else min = pos + 1;
    }
    TRACE("root %p dir %p id %04x not found\n", root, dir, id );
    return NULL;
}


/**********************************************************************
 *  find_entry_by_name
 *
 * Find an entry by name in a resource directory
 */
static const IMAGE_RESOURCE_DIRECTORY *find_entry_by_name( const IMAGE_RESOURCE_DIRECTORY *dir,
                                                           LPCWSTR name, const void *root,
                                                           int want_dir )
{
    const IMAGE_RESOURCE_DIRECTORY_ENTRY *entry;
    const IMAGE_RESOURCE_DIR_STRING_U *str;
    int min, max, res, pos, namelen;

    if (IS_INTRESOURCE(name)) return find_entry_by_id( dir, LOWORD(name), root, want_dir );
    entry = (const IMAGE_RESOURCE_DIRECTORY_ENTRY *)(dir + 1);
    namelen = wcslen(name);
    min = 0;
    max = dir->NumberOfNamedEntries - 1;
    while (min <= max)
    {
        pos = (min + max) / 2;
        str = (const IMAGE_RESOURCE_DIR_STRING_U *)((const char *)root + entry[pos].NameOffset);
        res = wcsncmp( name, str->NameString, str->Length );
        if (!res && namelen == str->Length)
        {
            if (!entry[pos].DataIsDirectory == !want_dir)
            {
                TRACE("root %p dir %p name %s ret %p\n",
                      root, dir, debugstr_w(name), (const char*)root + entry[pos].OffsetToDirectory);
                return (const IMAGE_RESOURCE_DIRECTORY *)((const char *)root + entry[pos].OffsetToDirectory);
            }
            break;
        }
        if (res < 0) max = pos - 1;
        else min = pos + 1;
    }
    TRACE("root %p dir %p name %s not found\n", root, dir, debugstr_w(name) );
    return NULL;
}


/**********************************************************************
 *  find_entry
 *
 * Find a resource entry
 */
static NTSTATUS find_entry( HMODULE hmod, const LDR_RESOURCE_INFO *info,
                            ULONG level, const void **ret, int want_dir )
{
    ULONG size;
    const void *root;
    const IMAGE_RESOURCE_DIRECTORY *resdirptr;
    WORD list[9];  /* list of languages to try */
    int i, pos = 0;

    root = RtlImageDirectoryEntryToData( hmod, TRUE, IMAGE_DIRECTORY_ENTRY_RESOURCE, &size );
    if (!root) return STATUS_RESOURCE_DATA_NOT_FOUND;
    if (size < sizeof(*resdirptr)) return STATUS_RESOURCE_DATA_NOT_FOUND;
    resdirptr = root;

    if (!level--) goto done;
    if (!(*ret = find_entry_by_name( resdirptr, (LPCWSTR)info->Type, root, want_dir || level )))
        return STATUS_RESOURCE_TYPE_NOT_FOUND;
    if (!level--) return STATUS_SUCCESS;

    resdirptr = *ret;
    if (!(*ret = find_entry_by_name( resdirptr, (LPCWSTR)info->Name, root, want_dir || level )))
        return STATUS_RESOURCE_NAME_NOT_FOUND;
    if (!level--) return STATUS_SUCCESS;
    if (level) return STATUS_INVALID_PARAMETER;  /* level > 3 */

    /* 1. specified language */
    pos = push_language( list, pos, info->Language );

    /* 2. specified language with neutral sublanguage */
    pos = push_language( list, pos, MAKELANGID( PRIMARYLANGID(info->Language), SUBLANG_NEUTRAL ) );

    /* 3. neutral language with neutral sublanguage */
    pos = push_language( list, pos, MAKELANGID( LANG_NEUTRAL, SUBLANG_NEUTRAL ) );

    /* if no explicitly specified language, try some defaults */
    if (PRIMARYLANGID(info->Language) == LANG_NEUTRAL)
    {
        LANGID user_lang, user_neutral_lang, system_lang;

        get_resource_lcids( &user_lang, &user_neutral_lang, &system_lang );

        /* user defaults, unless SYS_DEFAULT sublanguage specified  */
        if (SUBLANGID(info->Language) != SUBLANG_SYS_DEFAULT)
        {
            /* 4. current thread locale language */
            pos = push_language( list, pos, LANGIDFROMLCID(NtCurrentTeb()->CurrentLocale) );

            /* 5. user locale language */
            pos = push_language( list, pos, user_lang );

            /* 6. user locale language with neutral sublanguage  */
            pos = push_language( list, pos, user_neutral_lang );
        }

        /* 7. system locale language */
        pos = push_language( list, pos, system_lang );

        /* 8. system locale language with neutral sublanguage */
        pos = push_language( list, pos, PRIMARYLANGID( system_lang ));

        /* 9. English */
        pos = push_language( list, pos, MAKELANGID( LANG_ENGLISH, SUBLANG_DEFAULT ) );
    }

    resdirptr = *ret;
    for (i = 0; i < pos; i++)
        if ((*ret = find_entry_by_id( resdirptr, list[i], root, want_dir ))) return STATUS_SUCCESS;

    /* if no explicitly specified language, return the first entry */
    if (PRIMARYLANGID(info->Language) == LANG_NEUTRAL)
    {
        if ((*ret = find_first_entry( resdirptr, root, want_dir ))) return STATUS_SUCCESS;
    }
    return STATUS_RESOURCE_LANG_NOT_FOUND;

done:
    *ret = resdirptr;
    return STATUS_SUCCESS;
}


/* ===================== MUI satellite resource fallback =====================
 * Many Microsoft modules (e.g. iisres.dll) keep only icons/bitmaps in the main
 * image and split STRING / MESSAGETABLE / DIALOG resources into a
 * <dir>\<lang>\<name>.mui satellite. Windows redirects FindResource/LoadString
 * to the satellite transparently; Wine historically looked only in the main
 * module, so LoadString returned 0 and left ERROR_RESOURCE_TYPE_NOT_FOUND in
 * last-error. This implements the redirect at the LdrFindResource chokepoint. */

static inline SIZE_T mui_strlenW( const WCHAR *s )
{
    const WCHAR *p = s;
    while (*p) p++;
    return p - s;
}

static RTL_CRITICAL_SECTION mui_cs;
static RTL_CRITICAL_SECTION_DEBUG mui_cs_debug =
{
    0, 0, &mui_cs,
    { &mui_cs_debug.ProcessLocksList, &mui_cs_debug.ProcessLocksList },
    0, 0, { (DWORD_PTR)(__FILE__ ": mui_cs") }
};
static RTL_CRITICAL_SECTION mui_cs = { &mui_cs_debug, -1, 0, 0, 0, 0 };

struct mui_satellite
{
    HMODULE     base;        /* original module */
    HMODULE     sat;         /* mapped satellite base, NULL = probed/none */
    const char *sat_start;
    const char *sat_end;
};
static struct mui_satellite mui_cache[512];
static unsigned int mui_cache_count;

/* map <path> (a .mui PE) as an image section; return base and fill *map_size */
static HMODULE map_one_satellite( const WCHAR *path, SIZE_T *map_size )
{
    UNICODE_STRING nt_name;
    OBJECT_ATTRIBUTES attr;
    IO_STATUS_BLOCK io;
    HANDLE file, section;
    NTSTATUS status;
    void *base = NULL;
    SIZE_T size = 0;

    if (!RtlDosPathNameToNtPathName_U( path, &nt_name, NULL, NULL )) return NULL;
    InitializeObjectAttributes( &attr, &nt_name, OBJ_CASE_INSENSITIVE, 0, NULL );
    status = NtOpenFile( &file, GENERIC_READ | SYNCHRONIZE, &attr, &io,
                         FILE_SHARE_READ | FILE_SHARE_DELETE,
                         FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE );
    RtlFreeUnicodeString( &nt_name );
    if (!NT_SUCCESS(status)) return NULL;
    status = NtCreateSection( &section, SECTION_MAP_READ | SECTION_QUERY, NULL, NULL,
                              PAGE_READONLY, SEC_IMAGE, file );
    NtClose( file );
    if (!NT_SUCCESS(status)) return NULL;
    status = NtMapViewOfSection( section, NtCurrentProcess(), &base, 0, 0, NULL,
                                 &size, ViewShare, 0, PAGE_READONLY );
    NtClose( section );
    if (!NT_SUCCESS(status)) return NULL;
    *map_size = size;
    return base;
}

/* derive <dir>\<lang>\<name>.mui for hmod, trying preferred UI langs then en-US/en */
static HMODULE load_mui_satellite( HMODULE hmod, const char **sat_end )
{
    static const WCHAR enUS[] = {'e','n','-','U','S',0};
    static const WCHAR en[]   = {'e','n',0};
    static const WCHAR muiext[] = {'.','m','u','i',0};
    LDR_DATA_TABLE_ENTRY *ldr = NULL;
    WCHAR path[MAX_PATH * 2], langs[256];
    const WCHAR *full, *q, *dir_end, *name, *lang;
    ULONG num = 0, sz = ARRAY_SIZE(langs);
    HMODULE sat = NULL;
    SIZE_T map_size = 0, dir_len, name_len;
    int phase;

    if (LdrFindEntryForAddress( hmod, &ldr )) return NULL;
    if (!ldr->FullDllName.Buffer || !ldr->FullDllName.Length) return NULL;
    full = ldr->FullDllName.Buffer;

    dir_end = NULL;
    for (q = full; *q; q++) if (*q == '\\' || *q == '/') dir_end = q;
    if (!dir_end) return NULL;
    name = dir_end + 1;
    dir_len = dir_end - full;
    name_len = mui_strlenW( name );
    if (dir_len + name_len + 32 > ARRAY_SIZE(path)) return NULL;

    if (RtlGetThreadPreferredUILanguages( MUI_LANGUAGE_NAME, &num, langs, &sz ))
        langs[0] = langs[1] = 0;

    for (phase = 0; !sat && phase < 3; phase++)
    {
        const WCHAR *list_p = (phase == 0) ? langs : (phase == 1) ? enUS : en;
        for (lang = list_p; *lang; lang += (mui_strlenW(lang) + 1))
        {
            WCHAR *w = path;
            const WCHAR *r;
            memcpy( w, full, dir_len * sizeof(WCHAR) ); w += dir_len;
            *w++ = '\\';
            for (r = lang; *r; ) *w++ = *r++;
            *w++ = '\\';
            for (r = name; *r; ) *w++ = *r++;
            for (r = muiext; *r; ) *w++ = *r++;
            *w = 0;
            sat = map_one_satellite( path, &map_size );
            if (sat) break;
            if (phase != 0) break;   /* enUS / en are single entries */
        }
    }
    if (sat) *sat_end = (const char *)sat + map_size;
    return sat;
}

/* cached lookup/creation of the satellite module for hmod */
static HMODULE get_mui_satellite( HMODULE hmod )
{
    unsigned int i;
    HMODULE sat;
    const char *sat_end = NULL;

    RtlEnterCriticalSection( &mui_cs );
    for (i = 0; i < mui_cache_count; i++)
        if (mui_cache[i].base == hmod)
        {
            sat = mui_cache[i].sat;
            RtlLeaveCriticalSection( &mui_cs );
            return sat;
        }
    RtlLeaveCriticalSection( &mui_cs );

    sat = load_mui_satellite( hmod, &sat_end );

    RtlEnterCriticalSection( &mui_cs );
    for (i = 0; i < mui_cache_count; i++)
        if (mui_cache[i].base == hmod)
        {
            HMODULE existing = mui_cache[i].sat;
            RtlLeaveCriticalSection( &mui_cs );
            if (sat && sat != existing) NtUnmapViewOfSection( NtCurrentProcess(), sat );
            return existing;
        }
    if (mui_cache_count < ARRAY_SIZE(mui_cache))
    {
        mui_cache[mui_cache_count].base = hmod;
        mui_cache[mui_cache_count].sat = sat;
        mui_cache[mui_cache_count].sat_start = (const char *)sat;
        mui_cache[mui_cache_count].sat_end = sat_end;
        mui_cache_count++;
    }
    RtlLeaveCriticalSection( &mui_cs );
    if (sat) TRACE( "loaded MUI satellite %p for module %p\n", sat, hmod );
    return sat;
}

/* if entry lies inside a cached satellite of hmod, return that satellite base */
static HMODULE satellite_for_entry( HMODULE hmod, const void *entry )
{
    unsigned int i;
    HMODULE sat = NULL;
    RtlEnterCriticalSection( &mui_cs );
    for (i = 0; i < mui_cache_count; i++)
        if (mui_cache[i].base == hmod && mui_cache[i].sat &&
            (const char *)entry >= mui_cache[i].sat_start &&
            (const char *)entry <  mui_cache[i].sat_end)
        {
            sat = mui_cache[i].sat;
            break;
        }
    RtlLeaveCriticalSection( &mui_cs );
    return sat;
}

/* find_entry, with a transparent fallback to the module's .mui satellite */
static NTSTATUS find_entry_mui( HMODULE hmod, const LDR_RESOURCE_INFO *info,
                                ULONG level, const void **ret, int want_dir )
{
    NTSTATUS status = find_entry( hmod, info, level, ret, want_dir );
    if (status == STATUS_RESOURCE_TYPE_NOT_FOUND ||
        status == STATUS_RESOURCE_NAME_NOT_FOUND ||
        status == STATUS_RESOURCE_DATA_NOT_FOUND ||
        status == STATUS_RESOURCE_LANG_NOT_FOUND)
    {
        HMODULE sat = get_mui_satellite( hmod );
        if (sat)
        {
            const void *res2;
            NTSTATUS s2 = find_entry( sat, info, level, &res2, want_dir );
            if (s2 == STATUS_SUCCESS) { *ret = res2; return s2; }
        }
    }
    return status;
}


/**********************************************************************
 *	LdrFindResourceDirectory_U  (NTDLL.@)
 */
NTSTATUS WINAPI DECLSPEC_HOTPATCH LdrFindResourceDirectory_U( HMODULE hmod, const LDR_RESOURCE_INFO *info,
                                            ULONG level, const IMAGE_RESOURCE_DIRECTORY **dir )
{
    const void *res;
    NTSTATUS status;

    __TRY
    {
	if (info) TRACE( "module %p type %s name %s lang %04lx level %ld\n",
                     hmod, debugstr_w((LPCWSTR)info->Type),
                     level > 1 ? debugstr_w((LPCWSTR)info->Name) : "",
                     level > 2 ? info->Language : 0, level );

        status = find_entry_mui( hmod, info, level, &res, TRUE );
        if (status == STATUS_SUCCESS) *dir = res;
    }
    __EXCEPT_PAGE_FAULT
    {
        return GetExceptionCode();
    }
    __ENDTRY;
    return status;
}


/**********************************************************************
 *	LdrFindResource_U  (NTDLL.@)
 */
NTSTATUS WINAPI DECLSPEC_HOTPATCH LdrFindResource_U( HMODULE hmod, const LDR_RESOURCE_INFO *info,
                                   ULONG level, const IMAGE_RESOURCE_DATA_ENTRY **entry )
{
    const void *res;
    NTSTATUS status;

    __TRY
    {
	if (info) TRACE( "module %p type %s name %s lang %04lx level %ld\n",
                     hmod, debugstr_w((LPCWSTR)info->Type),
                     level > 1 ? debugstr_w((LPCWSTR)info->Name) : "",
                     level > 2 ? info->Language : 0, level );

        status = find_entry_mui( hmod, info, level, &res, FALSE );
        if (status == STATUS_SUCCESS) *entry = res;
    }
    __EXCEPT_PAGE_FAULT
    {
        return GetExceptionCode();
    }
    __ENDTRY;
    return status;
}


/* don't penalize other platforms with stuff needed on i386 for compatibility */
#ifdef __i386__
NTSTATUS WINAPI access_resource( HMODULE hmod, const IMAGE_RESOURCE_DATA_ENTRY *entry,
                                 void **ptr, ULONG *size )
#else
static inline NTSTATUS access_resource( HMODULE hmod, const IMAGE_RESOURCE_DATA_ENTRY *entry,
                                        void **ptr, ULONG *size )
#endif
{
    NTSTATUS status;

    __TRY
    {
        ULONG dirsize;
        HMODULE sat = satellite_for_entry( hmod, entry );

        if (sat) hmod = sat;
        if (!RtlImageDirectoryEntryToData( hmod, TRUE, IMAGE_DIRECTORY_ENTRY_RESOURCE, &dirsize ))
            status = STATUS_RESOURCE_DATA_NOT_FOUND;
        else
        {
            if (ptr)
            {
                BOOL is_data_file = is_data_file_module(hmod);
                hmod = (HMODULE)((ULONG_PTR)hmod & ~3);
                if (is_data_file)
                    *ptr = RtlImageRvaToVa( RtlImageNtHeader(hmod), hmod, entry->OffsetToData, NULL );
                else
                    *ptr = (char *)hmod + entry->OffsetToData;
            }
            if (size) *size = entry->Size;
            status = STATUS_SUCCESS;
        }
    }
    __EXCEPT_PAGE_FAULT
    {
        return GetExceptionCode();
    }
    __ENDTRY;
    return status;
}

/**********************************************************************
 *	LdrAccessResource  (NTDLL.@)
 *
 * NOTE
 * On x86, Shrinker, an executable compressor, depends on the
 * "call access_resource" instruction being there.
 */
#ifdef __i386__
__ASM_STDCALL_FUNC( LdrAccessResource, 16,
    "pushl %ebp\n\t"
    "movl %esp, %ebp\n\t"
    "subl $4,%esp\n\t"
    "pushl 24(%ebp)\n\t"
    "pushl 20(%ebp)\n\t"
    "pushl 16(%ebp)\n\t"
    "pushl 12(%ebp)\n\t"
    "pushl 8(%ebp)\n\t"
    "call " __ASM_STDCALL("access_resource",16) "\n\t"
    "leave\n\t"
    "ret $16"
)
#else
NTSTATUS WINAPI LdrAccessResource( HMODULE hmod, const IMAGE_RESOURCE_DATA_ENTRY *entry,
                                   void **ptr, ULONG *size )
{
    return access_resource( hmod, entry, ptr, size );
}
#endif

/**********************************************************************
 *	RtlFindMessage  (NTDLL.@)
 */
NTSTATUS WINAPI RtlFindMessage( HMODULE hmod, ULONG type, ULONG lang,
                                ULONG msg_id, const MESSAGE_RESOURCE_ENTRY **ret )
{
    const MESSAGE_RESOURCE_DATA *data;
    const MESSAGE_RESOURCE_BLOCK *block;
    const IMAGE_RESOURCE_DATA_ENTRY *rsrc;
    LDR_RESOURCE_INFO info;
    NTSTATUS status;
    void *ptr;
    unsigned int i;

    info.Type     = type;
    info.Name     = 1;
    info.Language = lang;

    if ((status = LdrFindResource_U( hmod, &info, 3, &rsrc )) != STATUS_SUCCESS)
        return status;
    if ((status = LdrAccessResource( hmod, rsrc, &ptr, NULL )) != STATUS_SUCCESS)
        return status;

    data = ptr;
    block = data->Blocks;
    for (i = 0; i < data->NumberOfBlocks; i++, block++)
    {
        if (msg_id >= block->LowId && msg_id <= block->HighId)
        {
            const MESSAGE_RESOURCE_ENTRY *entry;

            entry = (const MESSAGE_RESOURCE_ENTRY *)((const char *)data + block->OffsetToEntries);
            for (i = msg_id - block->LowId; i > 0; i--)
                entry = (const MESSAGE_RESOURCE_ENTRY *)((const char *)entry + entry->Length);
            *ret = entry;
            return STATUS_SUCCESS;
        }
    }
    return STATUS_MESSAGE_NOT_FOUND;
}
