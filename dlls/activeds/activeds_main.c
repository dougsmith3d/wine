/*
 * Implementation of the Active Directory Service Interface
 *
 * Copyright 2005 Detlef Riekenberg
 * Copyright 2019 Dmitry Timoshkov
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

#define COBJMACROS

#include "windef.h"
#include "winbase.h"
#include "winuser.h"

#include "objbase.h"
#include "initguid.h"
#include "iads.h"
#include "adshlp.h"
#include "adserr.h"
#include "lmcons.h"
#include "lmwksta.h"
#include "lmapibuf.h"
#include "lmerr.h"

#include "wine/debug.h"

WINE_DEFAULT_DEBUG_CHANNEL(activeds);

/*****************************************************
 * ADsGetObject     [ACTIVEDS.3]
 */
HRESULT WINAPI ADsGetObject(LPCWSTR path, REFIID riid, void **obj)
{
    HRESULT hr;

    TRACE("(%s, %s, %p)\n", debugstr_w(path), wine_dbgstr_guid(riid), obj);

    hr = ADsOpenObject(path, NULL, NULL, ADS_SECURE_AUTHENTICATION, riid, obj);
    if (hr != S_OK && hr != E_ADS_BAD_PATHNAME)
        hr = ADsOpenObject(path, NULL, NULL, 0, riid, obj);
    return hr;
}

/*****************************************************
 * ADsBuildEnumerator    [ACTIVEDS.4]
 */
HRESULT WINAPI ADsBuildEnumerator(IADsContainer * pADsContainer, IEnumVARIANT** ppEnumVariant)
{
    FIXME("(%p)->(%p)!stub\n",pADsContainer, ppEnumVariant);
    return E_NOTIMPL;
}

/*****************************************************
 * ADsFreeEnumerator     [ACTIVEDS.5]
 */
HRESULT WINAPI ADsFreeEnumerator(IEnumVARIANT* pEnumVariant)
{
    FIXME("(%p)!stub\n",pEnumVariant);
    return E_NOTIMPL;
}

/*****************************************************
 * ADsEnumerateNext     [ACTIVEDS.6]
 */
HRESULT WINAPI ADsEnumerateNext(IEnumVARIANT* pEnumVariant, ULONG cElements, VARIANT* pvar, ULONG * pcElementsFetched)
{
    FIXME("(%p)->(%lu, %p, %p)!stub\n",pEnumVariant, cElements, pvar, pcElementsFetched);
    return E_NOTIMPL;
}

/*****************************************************
 * ADsBuildVarArrayStr     [ACTIVEDS.7]
 */
HRESULT WINAPI ADsBuildVarArrayStr(LPWSTR *str, DWORD count, VARIANT *var)
{
    HRESULT hr;
    SAFEARRAY *sa;
    LONG idx, end = count;

    TRACE("(%p, %lu, %p)\n", str, count, var);

    if (!var) return E_ADS_BAD_PARAMETER;

    sa = SafeArrayCreateVector(VT_VARIANT, 0, count);
    if (!sa) return E_OUTOFMEMORY;

    VariantInit(var);
    for (idx = 0; idx < end; idx++)
    {
        VARIANT item;

        V_VT(&item) = VT_BSTR;
        V_BSTR(&item) = SysAllocString(str[idx]);
        if (!V_BSTR(&item))
        {
            hr = E_OUTOFMEMORY;
            goto fail;
        }

        hr = SafeArrayPutElement(sa, &idx, &item);
        SysFreeString(V_BSTR(&item));
        if (hr != S_OK) goto fail;
    }

    V_VT(var) = VT_ARRAY | VT_VARIANT;
    V_ARRAY(var) = sa;
    return S_OK;

fail:
    SafeArrayDestroy(sa);
    return hr;
}

/*****************************************************
 * ADsBuildVarArrayInt     [ACTIVEDS.8]
 */
HRESULT WINAPI ADsBuildVarArrayInt(LPDWORD values, DWORD count, VARIANT* var)
{
    HRESULT hr;
    SAFEARRAY *sa;
    LONG idx, end = count;

    TRACE("(%p, %lu, %p)\n", values, count, var);

    if (!var) return E_ADS_BAD_PARAMETER;

    sa = SafeArrayCreateVector(VT_VARIANT, 0, count);
    if (!sa) return E_OUTOFMEMORY;

    VariantInit(var);
    for (idx = 0; idx < end; idx++)
    {
        VARIANT item;

        V_VT(&item) = VT_I4;
        V_UI4(&item) = values[idx];

        hr = SafeArrayPutElement(sa, &idx, &item);
        if (hr != S_OK)
        {
            SafeArrayDestroy(sa);
            return hr;
        }
    }

    V_VT(var) = VT_ARRAY | VT_VARIANT;
    V_ARRAY(var) = sa;
    return S_OK;
}

/*****************************************************
 * ADsOpenObject     [ACTIVEDS.9]
 */

/* Minimal WinNT:// ADSI namespace provider.
 *
 * Wine ships only the LDAP provider; apps that resolve the local machine's
 * domain/workgroup via `new DirectoryEntry("WinNT://" + machine).Parent.Name`
 * (e.g. SharePoint's SPServer.Domain) get a failed bind. Implement just enough
 * IADs (Name/ADsPath/Parent) to answer that, resolving the workgroup name via
 * NetWkstaGetInfo. */
typedef struct
{
    IADs IADs_iface;
    LONG ref;
    BSTR name;
    BSTR adspath;
    BSTR parent;
} winnt_object;

static inline winnt_object *impl_from_winnt_IADs(IADs *iface)
{
    return CONTAINING_RECORD(iface, winnt_object, IADs_iface);
}

static HRESULT WINAPI winnt_QueryInterface(IADs *iface, REFIID riid, void **obj)
{
    winnt_object *o = impl_from_winnt_IADs(iface);
    if (!obj) return E_INVALIDARG;
    if (IsEqualGUID(riid, &IID_IUnknown) || IsEqualGUID(riid, &IID_IDispatch) ||
        IsEqualGUID(riid, &IID_IADs))
    {
        IADs_AddRef(&o->IADs_iface);
        *obj = &o->IADs_iface;
        return S_OK;
    }
    *obj = NULL;
    return E_NOINTERFACE;
}

static ULONG WINAPI winnt_AddRef(IADs *iface)
{
    winnt_object *o = impl_from_winnt_IADs(iface);
    return InterlockedIncrement(&o->ref);
}

static ULONG WINAPI winnt_Release(IADs *iface)
{
    winnt_object *o = impl_from_winnt_IADs(iface);
    LONG ref = InterlockedDecrement(&o->ref);
    if (!ref)
    {
        SysFreeString(o->name);
        SysFreeString(o->adspath);
        SysFreeString(o->parent);
        free(o);
    }
    return ref;
}

static HRESULT WINAPI winnt_GetTypeInfoCount(IADs *iface, UINT *count)
{
    if (count) *count = 0;
    return S_OK;
}
static HRESULT WINAPI winnt_GetTypeInfo(IADs *iface, UINT i, LCID lcid, ITypeInfo **ti)
{
    return E_NOTIMPL;
}
static HRESULT WINAPI winnt_GetIDsOfNames(IADs *iface, REFIID riid, LPOLESTR *names,
                                          UINT count, LCID lcid, DISPID *dispid)
{
    return E_NOTIMPL;
}
static HRESULT WINAPI winnt_Invoke(IADs *iface, DISPID dispid, REFIID riid, LCID lcid,
                                   WORD flags, DISPPARAMS *params, VARIANT *result,
                                   EXCEPINFO *ei, UINT *err)
{
    return E_NOTIMPL;
}

static HRESULT WINAPI winnt_get_Name(IADs *iface, BSTR *retval)
{
    winnt_object *o = impl_from_winnt_IADs(iface);
    if (!retval) return E_INVALIDARG;
    *retval = SysAllocString(o->name);
    return *retval ? S_OK : E_OUTOFMEMORY;
}
static HRESULT WINAPI winnt_get_Class(IADs *iface, BSTR *retval)
{
    if (retval) *retval = NULL;
    return E_NOTIMPL;
}
static HRESULT WINAPI winnt_get_GUID(IADs *iface, BSTR *retval)
{
    if (retval) *retval = NULL;
    return E_NOTIMPL;
}
static HRESULT WINAPI winnt_get_ADsPath(IADs *iface, BSTR *retval)
{
    winnt_object *o = impl_from_winnt_IADs(iface);
    if (!retval) return E_INVALIDARG;
    *retval = SysAllocString(o->adspath);
    return *retval ? S_OK : E_OUTOFMEMORY;
}
static HRESULT WINAPI winnt_get_Parent(IADs *iface, BSTR *retval)
{
    winnt_object *o = impl_from_winnt_IADs(iface);
    if (!retval) return E_INVALIDARG;
    if (!o->parent) return E_ADS_BAD_PATHNAME;
    *retval = SysAllocString(o->parent);
    return *retval ? S_OK : E_OUTOFMEMORY;
}
static HRESULT WINAPI winnt_get_Schema(IADs *iface, BSTR *retval)
{
    if (retval) *retval = NULL;
    return E_NOTIMPL;
}
static HRESULT WINAPI winnt_GetInfo(IADs *iface) { return S_OK; }
static HRESULT WINAPI winnt_SetInfo(IADs *iface) { return S_OK; }
static HRESULT WINAPI winnt_Get(IADs *iface, BSTR name, VARIANT *prop)
{
    return E_NOTIMPL;
}
static HRESULT WINAPI winnt_Put(IADs *iface, BSTR name, VARIANT prop)
{
    return E_NOTIMPL;
}
static HRESULT WINAPI winnt_GetEx(IADs *iface, BSTR name, VARIANT *prop)
{
    return E_NOTIMPL;
}
static HRESULT WINAPI winnt_PutEx(IADs *iface, LONG code, BSTR name, VARIANT prop)
{
    return E_NOTIMPL;
}
static HRESULT WINAPI winnt_GetInfoEx(IADs *iface, VARIANT name, LONG reserved)
{
    return E_NOTIMPL;
}

static const IADsVtbl winnt_IADs_vtbl =
{
    winnt_QueryInterface,
    winnt_AddRef,
    winnt_Release,
    winnt_GetTypeInfoCount,
    winnt_GetTypeInfo,
    winnt_GetIDsOfNames,
    winnt_Invoke,
    winnt_get_Name,
    winnt_get_Class,
    winnt_get_GUID,
    winnt_get_ADsPath,
    winnt_get_Parent,
    winnt_get_Schema,
    winnt_GetInfo,
    winnt_SetInfo,
    winnt_Get,
    winnt_Put,
    winnt_GetEx,
    winnt_PutEx,
    winnt_GetInfoEx
};

/* Workgroup/domain name of this machine, as a BSTR ("WORKGROUP" fallback). */
static BSTR winnt_get_langroup(void)
{
    WKSTA_INFO_100 *info = NULL;
    BSTR ret = NULL;
    if (NetWkstaGetInfo(NULL, 100, (BYTE **)&info) == NERR_Success && info && info->wki100_langroup)
        ret = SysAllocString(info->wki100_langroup);
    if (info) NetApiBufferFree(info);
    if (!ret) ret = SysAllocString(L"WORKGROUP");
    return ret;
}

static HRESULT WinNT_create(LPCWSTR path, REFIID riid, void **obj)
{
    winnt_object *o;
    const WCHAR *rest, *last;
    HRESULT hr;

    *obj = NULL;
    /* path looks like "WinNT:" or "WinNT://A/B/..." */
    rest = path + 6; /* skip "WinNT:" */
    while (*rest == '/') rest++;

    if (!(o = calloc(1, sizeof(*o)))) return E_OUTOFMEMORY;
    o->IADs_iface.lpVtbl = &winnt_IADs_vtbl;
    o->ref = 1;
    o->adspath = SysAllocString(path);

    if (!*rest)
    {
        /* the namespace root "WinNT:" */
        o->name = SysAllocString(L"WinNT:");
        o->parent = NULL;
    }
    else
    {
        WCHAR buf[512];
        last = wcsrchr(rest, '/');
        o->name = SysAllocString(last ? last + 1 : rest);
        if (last)
        {
            size_t n = last - path;
            if (n < ARRAY_SIZE(buf))
            {
                memcpy(buf, path, n * sizeof(WCHAR));
                buf[n] = 0;
                o->parent = SysAllocString(buf);
            }
        }
        else
        {
            /* single component (the machine): parent is the workgroup/domain */
            BSTR grp = winnt_get_langroup();
            swprintf(buf, ARRAY_SIZE(buf), L"WinNT://%s", grp);
            o->parent = SysAllocString(buf);
            SysFreeString(grp);
        }
    }

    hr = IADs_QueryInterface(&o->IADs_iface, riid, obj);
    IADs_Release(&o->IADs_iface);
    return hr;
}

HRESULT WINAPI ADsOpenObject(LPCWSTR path, LPCWSTR user, LPCWSTR password, DWORD reserved, REFIID riid, void **obj)
{
    HRESULT hr;
    HKEY hkey, hprov;
    WCHAR provider[MAX_PATH], progid[MAX_PATH];
    DWORD idx = 0;

    TRACE("(%s,%s,%lu,%s,%p)\n", debugstr_w(path), debugstr_w(user), reserved, debugstr_guid(riid), obj);

    if (!path || !riid || !obj)
        return E_INVALIDARG;

    hr = E_FAIL;

    if (!wcsnicmp(path, L"WinNT:", 6))
        return WinNT_create(path, riid, obj);

    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\ADs\\Providers", 0, KEY_READ, &hkey))
        return hr;

    for (;;)
    {
        if (RegEnumKeyW(hkey, idx++, provider, ARRAY_SIZE(provider)))
            break;

        TRACE("provider %s\n", debugstr_w(provider));

        if (!wcsnicmp(path, provider, wcslen(provider)) && path[wcslen(provider)] == ':')
        {
            LONG size;

            if (RegOpenKeyExW(hkey, provider, 0, KEY_READ, &hprov))
                break;

            size = ARRAY_SIZE(progid);
            if (!RegQueryValueW(hprov, NULL, progid, &size))
            {
                CLSID clsid;

                if (CLSIDFromProgID(progid, &clsid) == S_OK)
                {
                    IADsOpenDSObject *adsopen;
                    IDispatch *disp;

                    TRACE("ns %s => clsid %s\n", debugstr_w(progid), wine_dbgstr_guid(&clsid));
                    if (CoCreateInstance(&clsid, 0, CLSCTX_INPROC_SERVER, &IID_IADsOpenDSObject, (void **)&adsopen) == S_OK)
                    {
                        BSTR bpath, buser, bpassword;

                        bpath = SysAllocString(path);
                        buser = SysAllocString(user);
                        bpassword = SysAllocString(password);

                        hr = IADsOpenDSObject_OpenDSObject(adsopen, bpath, buser, bpassword, reserved, &disp);
                        if (hr == S_OK)
                        {
                            hr = IDispatch_QueryInterface(disp, riid, obj);
                            IDispatch_Release(disp);
                        }

                        SysFreeString(bpath);
                        SysFreeString(buser);
                        SysFreeString(bpassword);

                        IADsOpenDSObject_Release(adsopen);
                    }
                }
            }

            RegCloseKey(hprov);
            break;
        }
    }

    RegCloseKey(hkey);

    return hr;
}

/*****************************************************
 * ADsSetLastError    [ACTIVEDS.12]
 */
VOID WINAPI ADsSetLastError(DWORD dwErr, LPWSTR pszError, LPWSTR pszProvider)
{
    FIXME("(%ld,%p,%p)!stub\n", dwErr, pszError, pszProvider);
}

/*****************************************************
 * ADsGetLastError    [ACTIVEDS.13]
 */
HRESULT WINAPI ADsGetLastError(LPDWORD perror, LPWSTR errorbuf, DWORD errorbuflen, LPWSTR namebuf, DWORD namebuflen)
{
    FIXME("(%p,%p,%ld,%p,%ld)!stub\n", perror, errorbuf, errorbuflen, namebuf, namebuflen);
    return E_NOTIMPL;
}

/*****************************************************
 * AllocADsMem             [ACTIVEDS.14]
 */
LPVOID WINAPI AllocADsMem(DWORD cb)
{
    return malloc(cb);
}

/*****************************************************
 * FreeADsMem             [ACTIVEDS.15]
 */
BOOL WINAPI FreeADsMem(LPVOID pMem)
{
    free(pMem);
    return TRUE;
}

/*****************************************************
 * ReallocADsMem             [ACTIVEDS.16]
 */
LPVOID WINAPI ReallocADsMem(LPVOID pOldMem, DWORD cbOld, DWORD cbNew)
{
    return realloc(pOldMem, cbNew);
}

/*****************************************************
 * AllocADsStr             [ACTIVEDS.17]
 */
LPWSTR WINAPI AllocADsStr(LPWSTR pStr)
{
    TRACE("(%p)\n", pStr);
    return wcsdup(pStr);
}

/*****************************************************
 * FreeADsStr             [ACTIVEDS.18]
 */
BOOL WINAPI FreeADsStr(LPWSTR pStr)
{
    TRACE("(%p)\n", pStr);

    return FreeADsMem(pStr);
}

/*****************************************************
 * ReallocADsStr             [ACTIVEDS.19]
 */
BOOL WINAPI ReallocADsStr(LPWSTR *ppStr, LPWSTR pStr)
{
    FIXME("(%p,%p)!stub\n",*ppStr, pStr);
    return FALSE;
}

/*****************************************************
 * ADsEncodeBinaryData     [ACTIVEDS.20]
 */
HRESULT WINAPI ADsEncodeBinaryData(PBYTE pbSrcData, DWORD dwSrcLen, LPWSTR *ppszDestData)
{
    FIXME("(%p,%ld,%p)!stub\n", pbSrcData, dwSrcLen, *ppszDestData);
    return E_NOTIMPL;
}
