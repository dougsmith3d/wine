/*
 * Copyright 2023 Vijay Kiran Kamuju
 *
 * This library is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License v2.1+.
 */

#include <stdlib.h>

#include "wine/debug.h"
#include "websocket.h"

WINE_DEFAULT_DEBUG_CHANNEL(websocket);

#define WEB_SOCKET_MAX_VERSION 13

struct websocket
{
    LONG dummy;
};

HRESULT WINAPI WebSocketCreateClientHandle(const PWEB_SOCKET_PROPERTY properties,
    ULONG count, WEB_SOCKET_HANDLE *handle)
{
    struct websocket *ws;
    TRACE("(%p, %lu, %p)\n", properties, count, handle);
    if (!handle) return E_INVALIDARG;
    if (!(ws = calloc(1, sizeof(*ws)))) return E_OUTOFMEMORY;
    *handle = (WEB_SOCKET_HANDLE)ws;
    return S_OK;
}

/* .NET probes the supported protocol version via the client handshake headers. */
HRESULT WINAPI WebSocketBeginClientHandshake(WEB_SOCKET_HANDLE handle,
    const PSTR *subprotocols, ULONG subprotocol_count,
    const PSTR *extensions, ULONG extension_count,
    const PWEB_SOCKET_HTTP_HEADER initial_headers, ULONG initial_header_count,
    PWEB_SOCKET_HTTP_HEADER *additional_headers, ULONG *additional_header_count)
{
    static WEB_SOCKET_HTTP_HEADER headers[] =
    {
        { (PCHAR)"Connection",            10, (PCHAR)"Upgrade",   7 },
        { (PCHAR)"Upgrade",                7, (PCHAR)"websocket", 9 },
        { (PCHAR)"Sec-WebSocket-Version", 21, (PCHAR)"13",        2 },
    };
    TRACE("(%p, %p, %lu, %p, %lu, %p, %lu, %p, %p)\n", handle, subprotocols, subprotocol_count,
          extensions, extension_count, initial_headers, initial_header_count,
          additional_headers, additional_header_count);
    if (!handle) return E_INVALIDARG;
    if (additional_headers) *additional_headers = headers;
    if (additional_header_count) *additional_header_count = 3;
    return S_OK;
}

HRESULT WINAPI WebSocketGetGlobalProperty(WEB_SOCKET_PROPERTY_TYPE type, PVOID value, ULONG *size)
{
    TRACE("(%d, %p, %p)\n", type, value, size);
    switch (type)
    {
    case WEB_SOCKET_SUPPORTED_VERSIONS_PROPERTY_TYPE:
        if (!value || !size || *size < sizeof(ULONG)) return E_INVALIDARG;
        *(ULONG *)value = WEB_SOCKET_MAX_VERSION;
        *size = sizeof(ULONG);
        return S_OK;
    default:
        FIXME("property %d not implemented\n", type);
        return E_NOTIMPL;
    }
}

VOID WINAPI WebSocketAbortHandle(WEB_SOCKET_HANDLE handle)
{
    TRACE("(%p)\n", handle);
}

VOID WINAPI WebSocketDeleteHandle(WEB_SOCKET_HANDLE handle)
{
    TRACE("(%p)\n", handle);
    free(handle);
}
