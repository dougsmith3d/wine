/*
 * Implementation of svchost.exe
 *
 * Copyright 2007 Google (Roy Shea)
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

/* Usage:
 * Starting a service group:
 *
 *      svchost /k service_group_name
 */

#include <stdarg.h>

#include "windef.h"
#include "winbase.h"
#include "winreg.h"
#include "winsvc.h"
#include "winnt.h"
#include "wine/debug.h"

WINE_DEFAULT_DEBUG_CHANNEL(svchost);

/* Some shared-process services (notably modern MS service DLLs hosted via
 * svchost, e.g. SQL Server's AzureAttestService) export the undocumented
 * SvchostPushServiceGlobals entry point and *require* it to be called before
 * their ServiceMain runs: ServiceMain dereferences the pushed SVCHOST_GLOBAL_DATA
 * pointer, so a missing call is an immediate NULL-deref crash that aborts the
 * service start (and any installer custom action that starts the service).
 *
 * The structure is undocumented but stable: a leading block of well-known SID
 * pointers followed by a block of RPC helper function pointers.  We build a
 * conservative instance once (well-known SIDs filled in, every function-pointer
 * slot pointed at a benign stub) and hand it to the service.  This is enough for
 * the service to read any field or call any helper without faulting. */

static DWORD WINAPI svchost_globals_stub(void)
{
    /* generic benign helper: claim success (RPC_S_OK == 0) for any RPC helper
     * the hosted service may invoke through the globals table. */
    return 0;
}

#define SVCHOST_GLOBALS_SLOTS 64          /* 512 bytes; covers all known fields */
#define SVCHOST_GLOBALS_SID_SLOTS 18      /* leading well-known SID pointers     */

static void *build_svchost_globals(void)
{
    static void *globals[SVCHOST_GLOBALS_SLOTS];
    static BOOL built;
    struct { SID_IDENTIFIER_AUTHORITY auth; DWORD count; DWORD sub[2]; } sids[] = {
        {{SECURITY_NULL_SID_AUTHORITY},   1, {SECURITY_NULL_RID, 0}},
        {{SECURITY_WORLD_SID_AUTHORITY},  1, {SECURITY_WORLD_RID, 0}},
        {{SECURITY_LOCAL_SID_AUTHORITY},  1, {SECURITY_LOCAL_RID, 0}},
        {{SECURITY_NT_AUTHORITY},         1, {SECURITY_NETWORK_RID, 0}},
        {{SECURITY_NT_AUTHORITY},         1, {SECURITY_LOCAL_SYSTEM_RID, 0}},
        {{SECURITY_NT_AUTHORITY},         1, {SECURITY_LOCAL_SERVICE_RID, 0}},
        {{SECURITY_NT_AUTHORITY},         1, {SECURITY_NETWORK_SERVICE_RID, 0}},
        {{SECURITY_NT_AUTHORITY},         1, {SECURITY_BUILTIN_DOMAIN_RID, 0}},
        {{SECURITY_NT_AUTHORITY},         1, {SECURITY_AUTHENTICATED_USER_RID, 0}},
        {{SECURITY_NT_AUTHORITY},         1, {SECURITY_ANONYMOUS_LOGON_RID, 0}},
        {{SECURITY_NT_AUTHORITY},         2, {SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS}},
        {{SECURITY_NT_AUTHORITY},         2, {SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_USERS}},
        {{SECURITY_NT_AUTHORITY},         2, {SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_GUESTS}},
        {{SECURITY_NT_AUTHORITY},         2, {SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_POWER_USERS}},
        {{SECURITY_NT_AUTHORITY},         2, {SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ACCOUNT_OPS}},
        {{SECURITY_NT_AUTHORITY},         2, {SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_SYSTEM_OPS}},
        {{SECURITY_NT_AUTHORITY},         2, {SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_PRINT_OPS}},
        {{SECURITY_NT_AUTHORITY},         2, {SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_BACKUP_OPS}},
    };
    unsigned int i;

    if (built) return globals;

    /* every slot defaults to the benign stub so any unexpected field that is
     * read as (and called through) a function pointer cannot fault. */
    for (i = 0; i < SVCHOST_GLOBALS_SLOTS; i++)
        globals[i] = svchost_globals_stub;

    /* fill the leading well-known SID pointers. */
    for (i = 0; i < SVCHOST_GLOBALS_SID_SLOTS && i < ARRAY_SIZE(sids); i++)
    {
        PSID sid = NULL;
        if (AllocateAndInitializeSid(&sids[i].auth, (BYTE)sids[i].count,
                sids[i].sub[0], sids[i].sub[1], 0, 0, 0, 0, 0, 0, &sid) && sid)
            globals[i] = sid;
    }

    built = TRUE;
    return globals;
}

/* prototype matching the hosted DLL's expectation: the globals pointer is taken
 * from the second integer-register argument. We pass it in both so we satisfy
 * either calling shape. */
typedef void (WINAPI *SvchostPushServiceGlobals_t)(void *reserved, void *globals);

static const WCHAR service_reg_path[] = L"System\\CurrentControlSet\\Services";
static const WCHAR svchost_path[] = L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Svchost";

/* Allocate and initialize a WSTR containing the queried value */
static LPWSTR GetRegValue(HKEY service_key, const WCHAR *value_name)
{
    DWORD type;
    DWORD reg_size;
    DWORD size;
    LONG ret;
    LPWSTR value;

    WINE_TRACE("\n");

    ret = RegQueryValueExW(service_key, value_name, NULL, &type, NULL, &reg_size);
    if (ret != ERROR_SUCCESS)
    {
        return NULL;
    }

    /* Add space for potentially missing NULL terminators in initial alloc.
     * The worst case REG_MULTI_SZ requires two NULL terminators. */
    size = reg_size + (2 * sizeof(WCHAR));
    value = HeapAlloc(GetProcessHeap(), 0, size);

    ret = RegQueryValueExW(service_key, value_name, NULL, &type,
            (LPBYTE)value, &reg_size);
    if (ret != ERROR_SUCCESS)
    {
        HeapFree(GetProcessHeap(), 0, value);
        return NULL;
    }

    /* Explicitly NULL terminate the result */
    value[size / sizeof(WCHAR) - 1] = '\0';
    value[size / sizeof(WCHAR) - 2] = '\0';

    return value;
}

/* Allocate and initialize a WSTR containing the expanded string */
static LPWSTR ExpandEnv(LPWSTR string)
{
    DWORD size;
    LPWSTR expanded_string;

    WINE_TRACE("\n");

    size = 0;
    size = ExpandEnvironmentStringsW(string, NULL, size);
    if (size == 0)
    {
        WINE_ERR("cannot expand env vars in %s: %lu\n",
                wine_dbgstr_w(string), GetLastError());
        return NULL;
    }
    expanded_string = HeapAlloc(GetProcessHeap(), 0,
            (size + 1) * sizeof(WCHAR));
    if (ExpandEnvironmentStringsW(string, expanded_string, size) == 0)
    {
        WINE_ERR("cannot expand env vars in %s: %lu\n",
                wine_dbgstr_w(string), GetLastError());
        HeapFree(GetProcessHeap(), 0, expanded_string);
        return NULL;
    }
    return expanded_string;
}

/* Fill in service table entry for a specified service */
static BOOL AddServiceElem(LPWSTR service_name,
        SERVICE_TABLE_ENTRYW *service_table_entry)
{
    LONG ret;
    HKEY service_hkey = NULL;
    LPWSTR service_param_key = NULL;
    LPWSTR dll_name_short = NULL;
    LPWSTR dll_name_long = NULL;
    LPSTR dll_service_main = NULL;
    HMODULE library = NULL;
    LPSERVICE_MAIN_FUNCTIONW service_main_func = NULL;
    BOOL success = FALSE;
    DWORD reg_size;
    DWORD size;

    WINE_TRACE("Adding element for %s\n", wine_dbgstr_w(service_name));

    /* Construct registry path to the service's parameters key */
    size = lstrlenW(service_reg_path) + lstrlenW(L"\\") + lstrlenW(service_name) + lstrlenW(L"\\") +
           lstrlenW(L"Parameters") + 1;
    service_param_key = HeapAlloc(GetProcessHeap(), 0, size * sizeof(WCHAR));
    lstrcpyW(service_param_key, service_reg_path);
    lstrcatW(service_param_key, L"\\");
    lstrcatW(service_param_key, service_name);
    lstrcatW(service_param_key, L"\\");
    lstrcatW(service_param_key, L"Parameters");
    service_param_key[size - 1] = '\0';
    ret = RegOpenKeyExW(HKEY_LOCAL_MACHINE, service_param_key, 0,
            KEY_READ, &service_hkey);
    if (ret != ERROR_SUCCESS)
    {
        WINE_ERR("cannot open key %s, err=%ld\n",
                wine_dbgstr_w(service_param_key), ret);
        goto cleanup;
    }

    /* Find DLL associate with service from key */
    dll_name_short = GetRegValue(service_hkey, L"ServiceDll");
    if (!dll_name_short)
    {
        WINE_ERR("cannot find registry value ServiceDll for service %s\n",
                wine_dbgstr_w(service_name));
        RegCloseKey(service_hkey);
        goto cleanup;
    }

    /* Expand environment variables in ServiceDll name*/
    dll_name_long = ExpandEnv(dll_name_short);
    if (!dll_name_long)
    {
        WINE_ERR("failed to expand string %s\n",
                wine_dbgstr_w(dll_name_short));
        RegCloseKey(service_hkey);
        goto cleanup;
    }

    /* Look for alternate to default ServiceMain entry point */
    ret = RegQueryValueExA(service_hkey, "ServiceMain", NULL, NULL, NULL, &reg_size);
    if (ret == ERROR_SUCCESS)
    {
        /* Add space for potentially missing NULL terminator, allocate, and
         * fill with the registry value */
        size = reg_size + 1;
        dll_service_main = HeapAlloc(GetProcessHeap(), 0, size);
        ret = RegQueryValueExA(service_hkey, "ServiceMain", NULL, NULL,
                (LPBYTE)dll_service_main, &reg_size);
        if (ret != ERROR_SUCCESS)
        {
            RegCloseKey(service_hkey);
            goto cleanup;
        }
        dll_service_main[size - 1] = '\0';
    }
    RegCloseKey(service_hkey);

    /* Load the DLL and obtain a pointer to ServiceMain entry point */
    library = LoadLibraryExW(dll_name_long, NULL, LOAD_WITH_ALTERED_SEARCH_PATH);
    if (!library)
    {
        WINE_ERR("failed to load library %s, err=%lu\n",
                wine_dbgstr_w(dll_name_long), GetLastError());
        goto cleanup;
    }
    if (dll_service_main)
    {
        service_main_func =
            (LPSERVICE_MAIN_FUNCTIONW) GetProcAddress(library, dll_service_main);
    }
    else
    {
        service_main_func =
            (LPSERVICE_MAIN_FUNCTIONW) GetProcAddress(library, "ServiceMain");
    }
    if (!service_main_func)
    {
        WINE_ERR("cannot locate ServiceMain procedure in DLL for %s\n",
                wine_dbgstr_w(service_name));
        FreeLibrary(library);
        goto cleanup;
    }

    {
        SvchostPushServiceGlobals_t push_globals =
            (SvchostPushServiceGlobals_t)GetProcAddress(library, "SvchostPushServiceGlobals");
        if (push_globals)
        {
            void *globals = build_svchost_globals();
            WINE_TRACE("calling SvchostPushServiceGlobals for %s with globals %p\n",
                       wine_dbgstr_w(dll_name_long), globals);
            push_globals(globals, globals);
        }
    }

    /* Fill in the service table entry */
    service_table_entry->lpServiceName = service_name;
    service_table_entry->lpServiceProc = service_main_func;
    success = TRUE;

cleanup:
    HeapFree(GetProcessHeap(), 0, service_param_key);
    HeapFree(GetProcessHeap(), 0, dll_name_short);
    HeapFree(GetProcessHeap(), 0, dll_name_long);
    HeapFree(GetProcessHeap(), 0, dll_service_main);
    return success;
}

/* Initialize the service table for a list (REG_MULTI_SZ) of services */
static BOOL StartGroupServices(LPWSTR services)
{
    LPWSTR service_name = NULL;
    SERVICE_TABLE_ENTRYW *service_table = NULL;
    DWORD service_count;
    BOOL ret;

    /* Count the services to load */
    service_count = 0;
    service_name = services;
    while (*service_name != '\0')
    {
        ++service_count;
        service_name = service_name + lstrlenW(service_name);
        ++service_name;
    }
    WINE_TRACE("Service group contains %ld services\n", service_count);

    /* Populate the service table */
    service_table = HeapAlloc(GetProcessHeap(), 0,
            (service_count + 1) * sizeof(SERVICE_TABLE_ENTRYW));
    service_count = 0;
    service_name = services;
    while (*service_name != '\0')
    {
        if (!AddServiceElem(service_name, &service_table[service_count]))
        {
            HeapFree(GetProcessHeap(), 0, service_table);
            return FALSE;
        }
        ++service_count;
        service_name = service_name + lstrlenW(service_name);
        ++service_name;
    }
    service_table[service_count].lpServiceName = NULL;
    service_table[service_count].lpServiceProc = NULL;

    /* Start the services */
    if (!(ret = StartServiceCtrlDispatcherW(service_table)))
        WINE_ERR("StartServiceCtrlDispatcherW failed to start %s: %lu\n",
                wine_dbgstr_w(services), GetLastError());

    HeapFree(GetProcessHeap(), 0, service_table);
    return ret;
}

/* Find the list of services associated with a group name and start those
 * services */
static BOOL LoadGroup(PWCHAR group_name)
{
    HKEY group_hkey = NULL;
    LPWSTR services = NULL;
    LONG ret;

    WINE_TRACE("Loading service group for %s\n", wine_dbgstr_w(group_name));

    /* Lookup group_name value of svchost registry entry */
    ret = RegOpenKeyExW(HKEY_LOCAL_MACHINE, svchost_path, 0,
            KEY_READ, &group_hkey);
    if (ret != ERROR_SUCCESS)
    {
        WINE_ERR("cannot open key %s, err=%ld\n",
                wine_dbgstr_w(svchost_path), ret);
        return FALSE;
    }
    services = GetRegValue(group_hkey, group_name);
    RegCloseKey(group_hkey);
    if (!services)
    {
        WINE_ERR("cannot find registry value %s in %s\n",
                wine_dbgstr_w(group_name), wine_dbgstr_w(svchost_path));
        return FALSE;
    }

    /* Start services */
    if (!(ret = StartGroupServices(services)))
        WINE_TRACE("Failed to start service group\n");

    HeapFree(GetProcessHeap(), 0, services);
    return ret;
}

/* Load svchost group specified on the command line via the /k option */
int __cdecl wmain(int argc, WCHAR *argv[])
{
    int option_index;

    WINE_TRACE("\n");

    for (option_index = 1; option_index < argc; option_index++)
    {
        if (lstrcmpiW(argv[option_index], L"/k") == 0 || lstrcmpiW(argv[option_index], L"-k") == 0)
        {
            ++option_index;
            if (option_index >= argc)
            {
                WINE_ERR("Must specify group to initialize\n");
                return 0;
            }
            if (!LoadGroup(argv[option_index]))
            {
                WINE_ERR("Failed to load requested group: %s\n",
                        wine_dbgstr_w(argv[option_index]));
                return 0;
            }
        }
        else
        {
            WINE_FIXME("Unrecognized option: %s\n",
                    wine_dbgstr_w(argv[option_index]));
            return 0;
        }
    }

    return 0;
}
