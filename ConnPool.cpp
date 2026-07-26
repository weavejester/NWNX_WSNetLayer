#include "WSNetLayer.hpp"

#include <array>
#include <cstdint>
#include <libwebsockets.h>

// Map from connId to wsi: indexed as [connId - WS_CONN_START_ID]
static std::array<lws*, MAX_WS_CONN_IDS> g_WsConnToWsi {};
static std::array<uint32_t, MAX_WS_CONN_IDS> g_AvailableWsConnIds {};
static uint32_t g_AvailableWsConnIdCount = 0u;

#define IS_VALID_WS_CONNID(connId) \
    ((connId) >= WS_CONN_START_ID && (connId) < WS_CONN_START_ID + MAX_WS_CONN_IDS)

bool IsValidWsConnId(uint32_t connId)
{ return IS_VALID_WS_CONNID(connId); }

lws* GetWsiForWsConnId(uint32_t connId)
{
    if (!IS_VALID_WS_CONNID(connId))
        return nullptr;
    return g_WsConnToWsi[connId - WS_CONN_START_ID];
}

void SetWsiForWsConnId(uint32_t connId, lws* wsi)
{
    if (!IS_VALID_WS_CONNID(connId))
        return;
    g_WsConnToWsi[connId - WS_CONN_START_ID] = wsi;
}

void ClearWsiForWsConnId(uint32_t connId)
{
    if (!IS_VALID_WS_CONNID(connId))
        return;
    g_WsConnToWsi[connId - WS_CONN_START_ID] = nullptr;
}

void ResetWsConnIdPool()
{
    g_AvailableWsConnIdCount = MAX_WS_CONN_IDS;

    for (uint32_t i = 0; i < MAX_WS_CONN_IDS; ++i)
    {
        g_AvailableWsConnIds[i] = WS_CONN_START_ID + i;
    }
}

uint32_t AcquireWsConnId()
{
    if (g_AvailableWsConnIdCount == 0)
        return INVALID_WS_CONN_ID;

    return g_AvailableWsConnIds[--g_AvailableWsConnIdCount];
}

void ReleaseWsConnId(uint32_t connId)
{
    if (!IS_VALID_WS_CONNID(connId) || g_AvailableWsConnIdCount >= MAX_WS_CONN_IDS)
    {
        return;
    }

    g_AvailableWsConnIds[g_AvailableWsConnIdCount++] = connId;
}
