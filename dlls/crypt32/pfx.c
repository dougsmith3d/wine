/*
 * Copyright 2019 Hans Leidekker for CodeWeavers
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

#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "windef.h"
#include "winbase.h"
#include "wincrypt.h"
#include "snmp.h"
#include "crypt32_private.h"

#include "wine/debug.h"

WINE_DEFAULT_DEBUG_CHANNEL(crypt);

static HCRYPTPROV import_key( cert_store_data_t data, DWORD flags )
{
    HCRYPTPROV prov = 0;
    HCRYPTKEY cryptkey;
    DWORD size, acquire_flags;
    void *key;
    struct import_store_key_params params = { data, NULL, &size };

    if (CRYPT32_CALL( import_store_key, &params ) != STATUS_BUFFER_TOO_SMALL) return 0;

    acquire_flags = (flags & CRYPT_MACHINE_KEYSET) | CRYPT_NEWKEYSET;
    if (!CryptAcquireContextW( &prov, NULL, MS_ENHANCED_PROV_W, PROV_RSA_FULL, acquire_flags ))
    {
        if (GetLastError() != NTE_EXISTS) return 0;

        acquire_flags &= ~CRYPT_NEWKEYSET;
        if (!CryptAcquireContextW( &prov, NULL, MS_ENHANCED_PROV_W, PROV_RSA_FULL, acquire_flags ))
        {
            WARN( "CryptAcquireContextW failed %08lx\n", GetLastError() );
            return 0;
        }
    }

    params.buf = key = CryptMemAlloc( size );
    if (CRYPT32_CALL( import_store_key, &params ) ||
        !CryptImportKey( prov, key, size, 0, flags & CRYPT_EXPORTABLE, &cryptkey ))
    {
        WARN( "CryptImportKey failed %08lx\n", GetLastError() );
        CryptReleaseContext( prov, 0 );
        CryptMemFree( key );
        return 0;
    }
    CryptDestroyKey( cryptkey );
    CryptMemFree( key );
    return prov;
}

static BOOL set_key_context( const void *ctx, HCRYPTPROV prov )
{
    CERT_KEY_CONTEXT key_ctx;
    key_ctx.cbSize     = sizeof(key_ctx);
    key_ctx.hCryptProv = prov;
    key_ctx.dwKeySpec  = AT_KEYEXCHANGE;
    return CertSetCertificateContextProperty( ctx, CERT_KEY_CONTEXT_PROP_ID, 0, &key_ctx );
}

static WCHAR *get_provider_property( HCRYPTPROV prov, DWORD prop_id, DWORD *len )
{
    DWORD size = 0;
    WCHAR *ret;
    char *str;

    CryptGetProvParam( prov, prop_id, NULL, &size, 0 );
    if (!size) return NULL;
    if (!(str = CryptMemAlloc( size ))) return NULL;
    CryptGetProvParam( prov, prop_id, (BYTE *)str, &size, 0 );

    *len = MultiByteToWideChar( CP_ACP, 0, str, -1, NULL, 0 );
    if ((ret = CryptMemAlloc( *len * sizeof(WCHAR) ))) MultiByteToWideChar( CP_ACP, 0, str, -1, ret, *len );
    CryptMemFree( str );
    return ret;
}

static BOOL set_key_prov_info( const void *ctx, HCRYPTPROV prov, DWORD flags )
{
    CRYPT_KEY_PROV_INFO *prov_info;
    DWORD size, len_container, len_name;
    WCHAR *ptr, *container, *name;
    BOOL ret;

    if (!(container = get_provider_property( prov, PP_CONTAINER, &len_container ))) return FALSE;
    if (!(name = get_provider_property( prov, PP_NAME, &len_name )))
    {
        CryptMemFree( container );
        return FALSE;
    }
    if (!(prov_info = CryptMemAlloc( sizeof(*prov_info) + (len_container + len_name) * sizeof(WCHAR) )))
    {
        CryptMemFree( container );
        CryptMemFree( name );
        return FALSE;
    }

    ptr = (WCHAR *)(prov_info + 1);
    prov_info->pwszContainerName = ptr;
    lstrcpyW( prov_info->pwszContainerName, container );

    ptr += len_container;
    prov_info->pwszProvName = ptr;
    lstrcpyW( prov_info->pwszProvName, name );

    size = sizeof(prov_info->dwProvType);
    CryptGetProvParam( prov, PP_PROVTYPE, (BYTE *)&prov_info->dwProvType, &size, 0 );

    prov_info->dwFlags     = flags & CRYPT_MACHINE_KEYSET;
    prov_info->cProvParam  = 0;
    prov_info->rgProvParam = NULL;
    /* PP_KEYSPEC reports the keyspecs the CSP SUPPORTS (AT_SIGNATURE|AT_KEYEXCHANGE),
     * not which key the container actually holds. Storing that bitmask makes a
     * later CryptGetUserKey(dwKeySpec=3) fail NTE_NO_KEY. Probe the real key. */
    {
        HCRYPTKEY hkey;
        if (CryptGetUserKey( prov, AT_KEYEXCHANGE, &hkey ))
        {
            prov_info->dwKeySpec = AT_KEYEXCHANGE;
            CryptDestroyKey( hkey );
        }
        else if (CryptGetUserKey( prov, AT_SIGNATURE, &hkey ))
        {
            prov_info->dwKeySpec = AT_SIGNATURE;
            CryptDestroyKey( hkey );
        }
        else prov_info->dwKeySpec = AT_KEYEXCHANGE;
    }

    ret = CertSetCertificateContextProperty( ctx, CERT_KEY_PROV_INFO_PROP_ID, 0, prov_info );

    CryptMemFree( prov_info );
    CryptMemFree( name );
    CryptMemFree( container );
    return ret;
}

HCERTSTORE WINAPI PFXImportCertStore( CRYPT_DATA_BLOB *pfx, const WCHAR *password, DWORD flags )
{
    DWORD i = 0, size;
    HCERTSTORE store = NULL;
    HCRYPTPROV prov = 0;
    cert_store_data_t data = 0;
    struct open_cert_store_params open_params = { pfx, password, &data };
    struct close_cert_store_params close_params;

    if (!pfx)
    {
        SetLastError( ERROR_INVALID_PARAMETER );
        return NULL;
    }
    if (flags & ~(CRYPT_EXPORTABLE|CRYPT_USER_KEYSET|CRYPT_MACHINE_KEYSET|PKCS12_NO_PERSIST_KEY|PKCS12_ALWAYS_CNG_KSP))
    {
        FIXME( "flags %08lx not supported\n", flags );
        return NULL;
    }
    if (flags & PKCS12_ALWAYS_CNG_KSP)
    {
        FIXME( "flag PKCS12_ALWAYS_CNG_KSP ignored\n" );
    }
    if (CRYPT32_CALL( open_cert_store, &open_params )) return NULL;

    prov = import_key( data, flags );
    if (!prov) goto error;

    if (!(store = CertOpenStore( CERT_STORE_PROV_MEMORY, 0, 0, 0, NULL )))
    {
        WARN( "CertOpenStore failed %08lx\n", GetLastError() );
        goto error;
    }

    for (;;)
    {
        const void *ctx = NULL;
        void *cert;
        struct import_store_cert_params import_params = { data, i, NULL, &size };

        if (CRYPT32_CALL( import_store_cert, &import_params ) != STATUS_BUFFER_TOO_SMALL) break;
        import_params.buf = cert = CryptMemAlloc( size );
        if (!CRYPT32_CALL( import_store_cert, &import_params ))
            ctx = CertCreateContext( CERT_STORE_CERTIFICATE_CONTEXT, X509_ASN_ENCODING, cert, size, 0, NULL );
        CryptMemFree( cert );
        if (!ctx)
        {
            WARN( "CertCreateContext failed %08lx\n", GetLastError() );
            goto error;
        }
        if (flags & PKCS12_NO_PERSIST_KEY)
        {
            if (!set_key_context( ctx, prov ))
            {
                WARN( "failed to set context property %08lx\n", GetLastError() );
                CertFreeCertificateContext( ctx );
                goto error;
            }
        }
        else if (!set_key_prov_info( ctx, prov, flags ))
        {
            WARN( "failed to set provider info property %08lx\n", GetLastError() );
            CertFreeCertificateContext( ctx );
            goto error;
        }
        if (!CertAddCertificateContextToStore( store, ctx, CERT_STORE_ADD_ALWAYS, NULL ))
        {
            WARN( "CertAddCertificateContextToStore failed %08lx\n", GetLastError() );
            CertFreeCertificateContext( ctx );
            goto error;
        }
        CertFreeCertificateContext( ctx );
        i++;
    }
    close_params.data = data;
    CRYPT32_CALL( close_cert_store, &close_params );
    return store;

error:
    CryptReleaseContext( prov, 0 );
    CertCloseStore( store, 0 );
    close_params.data = data;
    CRYPT32_CALL( close_cert_store, &close_params );
    return NULL;
}

BOOL WINAPI PFXVerifyPassword( CRYPT_DATA_BLOB *pfx, const WCHAR *password, DWORD flags )
{
    FIXME( "(%p, %p, %08lx): stub\n", pfx, password, flags );
    return FALSE;
}

BOOL WINAPI PFXExportCertStore( HCERTSTORE store, CRYPT_DATA_BLOB *pfx, const WCHAR *password, DWORD flags )
{
    return PFXExportCertStoreEx( store, pfx, password, NULL, flags );
}

BOOL WINAPI PFXExportCertStoreEx( HCERTSTORE store, CRYPT_DATA_BLOB *pfx, const WCHAR *password, void *reserved,
                                  DWORD flags )
{
    PCCERT_CONTEXT cert, found = NULL;
    HCRYPTPROV_OR_NCRYPT_KEY_HANDLE prov = 0;
    HCRYPTKEY hkey = 0;
    DWORD keyspec = 0, blob_size = 0, pfx_size = 0;
    BOOL caller_free = FALSE, ret = FALSE;
    BYTE *key_blob = NULL;
    struct export_cert_store_params params;

    TRACE( "(%p, %p, %p, %p, %08lx)\n", store, pfx, password, reserved, flags );

    if (!store || !pfx) { SetLastError( ERROR_INVALID_PARAMETER ); return FALSE; }

    if (!(cert = CertEnumCertificatesInStore( store, NULL )))
    {
        SetLastError( CRYPT_E_NOT_FOUND );
        return FALSE;
    }
    if (CertEnumCertificatesInStore( store, cert ))
        FIXME( "exporting only the first certificate of a multi-cert store\n" );
    found = CertDuplicateCertificateContext( cert );

    /* Export the certificate's private key as a legacy MS PRIVATEKEYBLOB. */
    if ((flags & EXPORT_PRIVATE_KEYS) &&
        CryptAcquireCertificatePrivateKey( found, CRYPT_ACQUIRE_SILENT_FLAG, NULL, &prov, &keyspec, &caller_free ))
    {
        if (keyspec == 0xffffffff) /* CERT_NCRYPT_KEY_SPEC */
            FIXME( "CNG private key export not supported, exporting cert only\n" );
        else if (CryptGetUserKey( prov, keyspec, &hkey ) &&
                 CryptExportKey( hkey, 0, PRIVATEKEYBLOB, 0, NULL, &blob_size ) &&
                 (key_blob = CryptMemAlloc( blob_size )) &&
                 CryptExportKey( hkey, 0, PRIVATEKEYBLOB, 0, key_blob, &blob_size ))
        {
            /* got the private key */
        }
        else
        {
            WARN( "private key export failed %08lx\n", GetLastError() );
            CryptMemFree( key_blob );
            key_blob = NULL;
            blob_size = 0;
        }
    }

    params.cert          = found->pbCertEncoded;
    params.cert_size     = found->cbCertEncoded;
    params.key_blob      = key_blob;
    params.key_blob_size = blob_size;
    params.password      = password;

    /* size query */
    params.buf = NULL;
    params.buf_size = &pfx_size;
    CRYPT32_CALL( export_cert_store, &params );
    if (!pfx_size) { SetLastError( NTE_FAIL ); goto done; }

    if (!pfx->pbData)
    {
        pfx->cbData = pfx_size;
        ret = TRUE;
        goto done;
    }
    if (pfx->cbData < pfx_size)
    {
        pfx->cbData = pfx_size;
        SetLastError( ERROR_MORE_DATA );
        goto done;
    }

    params.buf = pfx->pbData;
    params.buf_size = &pfx->cbData;
    if (!CRYPT32_CALL( export_cert_store, &params )) ret = TRUE;   /* STATUS_SUCCESS */
    else SetLastError( NTE_FAIL );

done:
    if (hkey) CryptDestroyKey( hkey );
    if (prov && caller_free) CryptReleaseContext( prov, 0 );
    CryptMemFree( key_blob );
    if (found) CertFreeCertificateContext( found );
    return ret;
}
