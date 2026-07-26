#include "WSNetLayer.hpp"

// clang-format off
#include "API/CExoString.hpp"
#include "API/CNetLayer.hpp"
#include "Constants/Base.hpp"
#include "Globals.hpp"
#include "nwnx.hpp"
#include "nwn_api.hpp"

#include "API/CAppManager.hpp"
#include "API/CServerExoApp.hpp"
#include "API/CServerExoAppInternal.hpp"
#include "API/CExoNet.hpp"
#include "API/CExoNetInternal.hpp"
#include "API/CNetLayerInternal.hpp"
#include "API/CNetLayerPlayerInfo.hpp"
#include "API/CNetLayerWindow.hpp"
#include "API/CNWSMessage.hpp"
#include "API/CNWSPlayer.hpp"
// clang-format on

#include <arpa/inet.h>
#include <cstdint>
#include <libwebsockets.h>
#include <zstd.h>

#include <atomic>
#include <chrono>
#include <cstring>
#include <deque>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

using namespace NWNXLib;
using namespace NWNXLib::API;

//
// Per-connection user data stored in the lws per-wsi user buffer.
//
// NOTE: lws allocates this in its own heap; the destructor must be called
// explicitly in LWS_CALLBACK_CLOSED.
//
struct WSConnUserData
{
    uint32_t wsConnId;
    std::string ipv4;
    // One entry per outgoing WS frame (each vector has LWS_PRE padding at front).
    // Written under g_mtx; drained one-at-a-time by SERVER_WRITEABLE on the lws thread.
    std::deque<std::vector<uint8_t>> outQueue;

    // Set when the connection is admitted.
    std::chrono::steady_clock::time_point connectTime;

    // Set only when the player logs in.
    std::chrono::steady_clock::time_point loginTime;
    uint32_t playerId = Constants::PLAYERID_INVALIDID;
    std::string playerName = "";

    bool mustClose = false;
    std::string closeReason = "";

    // GN handshake state.
    bool gnhi_complete = false;
    uint64_t gnhi_client_caps = 0;
};

//
// Inbound message queued from the lws thread, delivered on the game thread MainLoop.
//
struct InboundMsg
{
    uint32_t wsConnId;
    std::vector<uint8_t> data;
};

//
// Global state
//
static lws_context* g_lws_context = nullptr;
static std::thread g_lws_thread;
static std::atomic<bool> g_lws_running { false };
static std::atomic<bool> g_server_running { false };

//
// Protects access to the shared state below; synchronises lws thread and game thread.
// Also protectes the ConnPool primitives.
//
static std::mutex g_mtx;

//
// Inbound messages produced by the lws thread, consumed by MainLoop on the game thread.
//
static std::vector<InboundMsg> g_inboundQueue;
static std::vector<uint32_t> g_disconnectWsConnId;
static std::vector<uint32_t> g_retiredWsConnId;

//
// Hooks
//
static Hooks::Hook s_CServerExoAppInternal_MainLoopHook_Init;
static Hooks::Hook s_CServerExoAppInternal_MainLoopHook;
static Hooks::Hook s_CNetLayerInternal_SendMessageToPlayerHook;
static Hooks::Hook s_CNetLayerInternal_SetPlayerConnectedHook;
static Hooks::Hook s_CNetLayerInternal_DisconnectPlayerHook;
static Hooks::Hook s_CNetLayerInternal_SendDirectMessageHook;
static Hooks::Hook s_CNetLayerInternal_GetPlayerAddressHook;
static Hooks::Hook s_CNetLayerInternal_GetPlayerAddressDataHook;
static Hooks::Hook s_CExoNetInternal_GetNetworkAddressStringHook;
static Hooks::Hook s_CExoNetInternal_GetCryptoStateForConnectionHook;
static Hooks::Hook s_CNetLayerWindow_FrameTimeout;

static void MarkWriteActivity(lws* wsi)
{
    lws_callback_on_writable(wsi);
    lws_cancel_service(g_lws_context);
}

//
// Outgoing queue helper — enqueues ONE WS frame.
// payload must already be the complete wire bytes to send.
//
static void QueueSendToWS(lws* wsi, const std::vector<uint8_t>& payload)
{
    auto* data = reinterpret_cast<WSConnUserData*>(lws_wsi_user(wsi));
    if (!data || payload.empty())
        return;

    std::vector<uint8_t> buf(LWS_PRE + payload.size());
    std::memcpy(buf.data() + LWS_PRE, payload.data(), payload.size());
    data->outQueue.push_back(std::move(buf));

    MarkWriteActivity(wsi);
}

//
// libwebsockets callback — runs on the LWS THREAD.
//
static int ws_callback(lws* wsi, enum lws_callback_reasons reason, void* user, void* in, size_t len)
{
    auto* data = reinterpret_cast<WSConnUserData*>(user);

    switch (reason)
    {
        case LWS_CALLBACK_ESTABLISHED:
        {
            if (!data)
                return -1;

            new (data) WSConnUserData {};

            std::string peerIPv4;
            std::string effectiveIPv4;

            char ipv4Buf[64] = {};
            lws_get_peer_simple(wsi, ipv4Buf, sizeof(ipv4Buf));
            data->ipv4 = peerIPv4 = ipv4Buf;
            if (TryGetForwardedForIPv4(wsi, effectiveIPv4))
                data->ipv4 = std::move(effectiveIPv4);

#define POLICY_REJECT(reason)                                                              \
    do                                                                                     \
    {                                                                                      \
        LOG_INFO("Connection from %s (via %s) rejected: %s.",                              \
            peerIPv4.empty() ? "<unknown>" : peerIPv4.c_str(),                             \
            effectiveIPv4.empty() ? "<unknown>" : effectiveIPv4.c_str(), reason);          \
        lws_close_reason(wsi, LWS_CLOSE_STATUS_POLICY_VIOLATION, (unsigned char*)(reason), \
            strlen(reason));                                                               \
    } while (0)

            std::lock_guard<std::mutex> lock(g_mtx);

            if (!IsPrivateIPv4(peerIPv4.c_str()))
            {
                POLICY_REJECT("Use a proxy with TLS to expose the WSNetLayer websocket publicly");
                return -1;
            }

            if (!g_server_running)
            {
                POLICY_REJECT("server not running");
                return -1;
            }

            {
                uint32_t unauthedFromIP = 0;
                for (uint32_t i = 0; i < MAX_WS_CONN_IDS; ++i)
                {
                    lws* existing = GetWsiForWsConnId(i + WS_CONN_START_ID);
                    if (!existing)
                        continue;
                    auto* d = reinterpret_cast<WSConnUserData*>(lws_wsi_user(existing));
                    if (d && d->playerId == Constants::PLAYERID_INVALIDID && d->ipv4 == data->ipv4)
                        ++unauthedFromIP;
                }
                if (unauthedFromIP >= MAX_UNAUTHED_CONN_PER_IP)
                {
                    POLICY_REJECT("too many unauthenticated connections from this IP");
                    return -1;
                }
            }

            data->wsConnId = AcquireWsConnId();
            if (data->wsConnId == INVALID_WS_CONN_ID)
            {
                POLICY_REJECT("server overloaded");
                return -1;
            }

            data->connectTime = std::chrono::steady_clock::now();
            SetWsiForWsConnId(data->wsConnId, wsi);

            LOG_INFO("Admitted peer %s (via %s) with connId 0x%x.", data->ipv4.c_str(),
                peerIPv4.c_str(), data->wsConnId);
            return 0;
        }

        case LWS_CALLBACK_RECEIVE:
        {
            if (!data || len < 1)
                return 0;

            const auto* pBuffer = reinterpret_cast<const uint8_t*>(in);

            std::vector<uint8_t> payload = { pBuffer, pBuffer + len };

            if (payload.empty())
                return 0;

            //
            // Before any BN or window messages, both sides must exchange GNHI.
            // The server discards all non-GNHI bytes until this completes.
            //
            if (!data->gnhi_complete)
            {
                if (payload.size() < 13 || payload[0] != 'G' || payload[1] != 'N' ||
                    payload[2] != 'H' || payload[3] != 'I')
                {
                    auto reason = payload[0] == 'G' ? "Bad GN handshake"
                                                    : "Expected GN handshake first";
                    lws_close_reason(wsi, LWS_CLOSE_STATUS_POLICY_VIOLATION, (unsigned char*)reason,
                        strlen(reason));
                    return -1;
                }

                uint8_t client_ver = payload[4];
                uint64_t client_caps;
                memcpy(&client_caps, payload.data() + 5, sizeof(client_caps));

                LOG_INFO("GNHI from connId 0x%x: ver=%u caps=0x%016lx.", data->wsConnId, client_ver,
                    client_caps);

                if (client_ver != NWNX_WSNETLAYER_PROTOCOL_VERSION)
                {
                    std::string reason = "Protocol version mismatch: client=" +
                        std::to_string(client_ver) +
                        " server=" + std::to_string(NWNX_WSNETLAYER_PROTOCOL_VERSION);
                    lws_close_reason(wsi, LWS_CLOSE_STATUS_POLICY_VIOLATION,
                        (unsigned char*)reason.c_str(), reason.size());
                    return -1;
                }

                // Caps are not yet allocated; mask is 0, so any unknown bits are not understood.
                // In the future, we can compute the intersection and handle it properly.
                constexpr uint64_t server_caps = 0;

                if (client_caps != server_caps)
                {
                    std::string reason = "Client sent invalid caps: 0x" +
                        std::to_string(client_caps);
                    lws_close_reason(wsi, LWS_CLOSE_STATUS_POLICY_VIOLATION,
                        (unsigned char*)reason.c_str(), reason.size());
                    return -1;
                }

                // Server's GNHI response: same format, server's version + caps.
                {
                    uint8_t resp[13] = {
                        'G',
                        'N',
                        'H',
                        'I',
                        NWNX_WSNETLAYER_PROTOCOL_VERSION,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                    };
                    memcpy(resp + 5, &server_caps, sizeof(server_caps));

                    std::lock_guard<std::mutex> lock(g_mtx);
                    data->gnhi_client_caps = client_caps;
                    auto& buf = data->outQueue.emplace_back(sizeof(resp) + LWS_PRE);
                    memcpy(buf.data() + LWS_PRE, resp, sizeof(resp));
                    lws_callback_on_writable(wsi);
                    data->gnhi_complete = true;
                }

                LOG_INFO("GN handshake complete for connId 0x%x.", data->wsConnId);
                return 0;
            }

            std::lock_guard<std::mutex> lock(g_mtx);

            if (data->playerId == Constants::PLAYERID_INVALIDID)
            {
                // Only allow pre-window messages until the player has authenticated and been
                // admitted into the game. The base game should do this too (no player ID), but a
                // sanity check can't hurt.
                if (payload[0] != 'B')
                {
                    return 0;
                }
            }

            InboundMsg msg;
            msg.wsConnId = data->wsConnId;
            msg.data = std::move(payload);
            g_inboundQueue.push_back(std::move(msg));
            return 0;
        }

        case LWS_CALLBACK_SERVER_WRITEABLE:
        {
            if (!data)
                return 0;

            std::lock_guard<std::mutex> lock(g_mtx);

            if (data->mustClose)
            {
                lws_close_reason(wsi, LWS_CLOSE_STATUS_NORMAL,
                    (unsigned char*)data->closeReason.c_str(), data->closeReason.size());
                return -1;
            }

            if (data->outQueue.empty())
                return 0;

            // Send one queued frame; re-request writable if more remain.
            auto& front = data->outQueue.front();
            const size_t payloadLen = front.size() - LWS_PRE;
            const int written = lws_write(wsi, front.data() + LWS_PRE, payloadLen,
                LWS_WRITE_BINARY);
            data->outQueue.pop_front();
            if (written < 0)
                return -1;

            if (!data->outQueue.empty())
                lws_callback_on_writable(wsi);
            return 0;
        }

        case LWS_CALLBACK_WS_PEER_INITIATED_CLOSE:
        {
            if (data)
            {
                std::lock_guard<std::mutex> lock(g_mtx);
                int len = lws_get_close_length(wsi);
                if (len)
                    data->closeReason = std::string((const char*)lws_get_close_payload(wsi), len);
                else
                    data->closeReason = "Peer closed connection";
                data->closeReason = SanitizeString(data->closeReason);
            }

            return 0;
        }

        case LWS_CALLBACK_CLOSED:
        {
            if (!data)
                return -1;

            std::lock_guard<std::mutex> lock(g_mtx);

            const uint32_t connId = data->wsConnId;
            lws* storedWsi = GetWsiForWsConnId(connId);

            if (storedWsi == wsi)
            {
                LOG_INFO("Closing WS connection with connId 0x%x: %s", connId,
                    data->closeReason.c_str());

                // Only queue a game-level disconnect if the player was authenticated.
                // Connections rejected during GN or BN handshake have no player to disconnect.
                if (data->playerId != Constants::PLAYERID_INVALIDID)
                    g_disconnectWsConnId.emplace_back(connId);

                ClearWsiForWsConnId(connId);
            }
            else
            {
                LOG_INFO("Closing detached WS connection with connId 0x%x: %s", connId,
                    data->closeReason.c_str());
            }

            if (connId != INVALID_WS_CONN_ID)
            {
                g_retiredWsConnId.emplace_back(connId);
            }

            data->~WSConnUserData();
            return 0;
        }

        default: return 0;
    }

    return 0;
}

//
// Hook: CNetLayerInternal::SendDirectMessage - game thread.
//
static BOOL CNetLayerInternal_SendDirectMessage_Hook(CNetLayerInternal* ni,
    CNetConnectionId nConnectionId, uint8_t* pData, uint32_t nMsgLength, uint32_t nPort)
{
    if (IsValidWsConnId(*nConnectionId))
    {
        std::lock_guard<std::mutex> lock(g_mtx);
        if (auto* wsi = GetWsiForWsConnId(*nConnectionId))
        {
            QueueSendToWS(wsi, std::vector<uint8_t>(pData, pData + nMsgLength));
        }
        return TRUE;
    }

    return s_CNetLayerInternal_SendDirectMessageHook->CallOriginal<BOOL>(ni, nConnectionId, pData,
        nMsgLength, nPort);
}

//
// Hook: CNetLayerInternal::SendMessageToPlayer — game thread.
//
static BOOL CNetLayerInternal_SendMessageToPlayer_Hook(CNetLayerInternal* ni, uint32_t nPlayerId,
    uint8_t* pBuffer, uint32_t nBufferSize, uint32_t nFlags)
{
    static constexpr uint32_t WS_BROADCAST_THRESHOLD = 0xfffffff0u;

    const auto SerializeForWS = [&]() -> std::vector<uint8_t>
    {
        auto buf = GetCurrentWriteBuffer();
        auto lastPtr = GetLastWritePtr();
        auto lastSize = GetLastWriteSize();

        // No payload, nothing to serialize; send header as-is.
        if (nBufferSize == 3)
            return { pBuffer, pBuffer + nBufferSize };

        if (nBufferSize > 3 && (lastPtr != pBuffer || lastSize != nBufferSize))
        {
            LOG_ERROR(
                "SendMessageToPlayer called with unexpected buffer (ptr=0x%p, size=%u); "
                "WSNetLayer bug: MessageWriter hooks missed the write? "
                "Or someone else wrote?",
                pBuffer, nBufferSize);
            return {};
        }

        std::vector<uint8_t> result;
        result.push_back(pBuffer[0]);
        result.push_back(pBuffer[1]);
        result.push_back(pBuffer[2]);
        auto serialized = SerializeFragBufferToWire(buf);
        result.insert(result.end(), serialized.begin(), serialized.end());
        buf.clear(); // just making sure in case the writer didn't.
        return result;
    };

    if (nPlayerId < WS_BROADCAST_THRESHOLD)
    {
        CNetConnectionId connId;
        ASSERT_OR_RETURN(ni->PlayerIdToConnectionId(nPlayerId, &connId), FALSE);

        std::lock_guard<std::mutex> lock(g_mtx);

        if (auto* wsi = GetWsiForWsConnId(*connId))
        {
            const auto result = SerializeForWS();
            if (result.empty())
                return FALSE;

            QueueSendToWS(wsi, result);
            return 1;
        }
    }

    else if (nPlayerId == Constants::PLAYERID_ALL_CLIENTS ||
        nPlayerId == Constants::PLAYERID_ALL_PLAYERS ||
        nPlayerId == Constants::PLAYERID_ALL_GAMEMASTERS)
    {
        std::lock_guard<std::mutex> lock(g_mtx);

        auto* srv = g_pAppManager->m_pServerExoApp;
        auto* nl = srv->GetNetLayer();

        for (auto& player : srv->GetPlayerList())
        {
            auto* pi = nl->GetPlayerInfo(player->m_nPlayerID);
            ASSERT(pi);

            if (nPlayerId == Constants::PLAYERID_ALL_GAMEMASTERS && !pi->m_bGameMasterPrivileges)
                continue;

            CNetConnectionId connId;
            if (!ni->PlayerIdToConnectionId(player->m_nPlayerID, &connId))
            {
                LOG_WARNING("PlayerIdToConnectionId failed for playerId=0x%08x; skipping.",
                    player->m_nPlayerID);
                continue;
            }

            if (auto* wsi = GetWsiForWsConnId(*connId))
            {
                const auto result = SerializeForWS();
                if (result.empty())
                    continue;
                QueueSendToWS(wsi, result);
            }
        }
    }

    return s_CNetLayerInternal_SendMessageToPlayerHook->CallOriginal<BOOL>(ni, nPlayerId, pBuffer,
        nBufferSize, nFlags);
}

//
// Hook: CNetLayerInternal::SetPlayerConnected - game thread.
//
static void CNetLayerInternal_SetPlayerConnected_Hook(CNetLayerInternal* ni, uint32_t nPlayerId)
{
    s_CNetLayerInternal_SetPlayerConnectedHook->CallOriginal<void>(ni, nPlayerId);

    CNetConnectionId connId;
    ASSERT_OR_RETURN(ni->PlayerIdToConnectionId(nPlayerId, &connId), );

    std::lock_guard<std::mutex> lock(g_mtx);

    if (auto* wsi = GetWsiForWsConnId(*connId))
    {
        auto* data = reinterpret_cast<WSConnUserData*>(lws_wsi_user(wsi));
        auto* pi = g_pAppManager->m_pServerExoApp->GetNetLayer()->GetPlayerInfo(nPlayerId);
        data->playerId = nPlayerId;
        data->playerName = pi->m_sPlayerName;
        data->loginTime = std::chrono::steady_clock::now();
    }
}

//
// Hook: CNetLayer::DisconnectPlayer — game thread.
// Intercepts game-initiated disconnects for WS players.
//
static BOOL CNetLayerInternal_DisconnectPlayer_Hook(CNetLayerInternal* ni, uint32_t nPlayerId,
    uint32_t nStrRef, BOOL /*bSendBNDP*/, BOOL bCDAuthFail, const CExoString& reason)
{
    CNetConnectionId connId;
    ASSERT_OR_RETURN(ni->PlayerIdToConnectionId(nPlayerId, &connId), FALSE);

    // Call back parent first to do the housekeeping. We do NOT send a BNDP; the websocket
    // client protocol has it's own close message.
    BOOL ret = s_CNetLayerInternal_DisconnectPlayerHook->CallOriginal<BOOL>(ni, nPlayerId, nStrRef,
        FALSE /*BNDP*/, bCDAuthFail, reason);

    {
        std::lock_guard<std::mutex> lock(g_mtx);

        if (auto* wsi = GetWsiForWsConnId(*connId))
        {
            auto* data = reinterpret_cast<WSConnUserData*>(lws_wsi_user(wsi));
            std::string safe_reason = reason.CStr();
            if (safe_reason.length() > 123)
                safe_reason = safe_reason.substr(0, 123);
            data->closeReason = safe_reason;
            data->mustClose = true;
            MarkWriteActivity(wsi);
        }
    }

    return ret;
}

static CNetPeer CNetLayerInternal_GetPlayerAddressData_Hook(CNetLayerInternal* ni,
    CNetConnectionId nConnectionId)
{
    if (*nConnectionId < WS_CONN_START_ID)
        return s_CNetLayerInternal_GetPlayerAddressDataHook->CallOriginal<CNetPeer>(ni,
            nConnectionId);

    std::lock_guard<std::mutex> lock(g_mtx);

    lws* wsi = GetWsiForWsConnId(*nConnectionId);
    ASSERT_OR_RETURN(wsi != nullptr, CNetPeer {});
    auto* data = reinterpret_cast<WSConnUserData*>(lws_wsi_user(wsi));

    CNetPeer peer {};
    peer.m_address.sin_family = AF_INET;
    peer.m_address.sin_port = htons(5121);
    peer.m_address.sin_addr.s_addr = inet_addr(data->ipv4.c_str());
    return peer;
}

static CExoString CExoNetInternal_GetNetworkAddressString_Hook(CExoNetInternal* ei,
    CNetConnectionId nConnectionId, BOOL bIncludePort)
{
    if (*nConnectionId < WS_CONN_START_ID)
        return s_CExoNetInternal_GetNetworkAddressStringHook->CallOriginal<CExoString>(ei,
            nConnectionId, bIncludePort);

    std::lock_guard<std::mutex> lock(g_mtx);

    lws* wsi = GetWsiForWsConnId(*nConnectionId);
    ASSERT_OR_RETURN(wsi != nullptr, "");

    auto* data = reinterpret_cast<WSConnUserData*>(lws_wsi_user(wsi));
    if (bIncludePort)
        return CExoString(data->ipv4.c_str()) + ":" + std::to_string(5121);
    else
        return CExoString(data->ipv4.c_str());
}

static CExoString CNetLayerInternal_GetPlayerAddress_Hook(CNetLayerInternal* ni, uint32_t nPlayerId,
    BOOL bIncludePort)
{
    CNetConnectionId connId;
    ASSERT_OR_RETURN(ni->PlayerIdToConnectionId(nPlayerId, &connId), "");

    if (*connId < WS_CONN_START_ID)
        return s_CNetLayerInternal_GetPlayerAddressHook->CallOriginal<CExoString>(ni, nPlayerId,
            bIncludePort);

    std::lock_guard<std::mutex> lock(g_mtx);

    lws* wsi = GetWsiForWsConnId(*connId);
    ASSERT_OR_RETURN(wsi != nullptr, "");

    return reinterpret_cast<WSConnUserData*>(lws_wsi_user(wsi))->ipv4;
}

//
// Hook: CExoNetInternal::GetCryptoStateForConnection — game thread.
//
static void* CExoNetInternal_GetCryptoStateForConnection_Hook(CExoNetInternal* ni,
    CNetConnectionId nConnection)
{
    static uint32_t dummyState[268 / 4];
    memset(&dummyState, 0, sizeof(dummyState));
    dummyState[0] = 1;
    dummyState[68 / 4] = 3;
    dummyState[264 / 4] = *nConnection * 0xCAFE % 0xFFFFFFFF;

    // Only consumer here is BNCS; but doesn't hurt to stub it out for all callers.
    if (GetWsiForWsConnId(*nConnection))
        return &dummyState;

    return s_CExoNetInternal_GetCryptoStateForConnectionHook->CallOriginal<void*>(ni, nConnection);
}

//
// Hook: CNetLayerWindow::FrameTimeout — game thread.
//
static BOOL CNetLayerWindow_FrameTimeout_Hook(CNetLayerWindow* self)
{
    // Don't run the sliding window timeout for WS connections.
    // WS connections have their own timeout mechanism built in.
    if (IsValidWsConnId(self->m_nConnectionId))
        return 0;

    return s_CNetLayerWindow_FrameTimeout->CallOriginal<BOOL>(self);
}

//
// Hook: CServerExoAppInternal::MainLoop — game thread.
// Drains the inbound queue that was filled by the lws thread.
//
static BOOL CServerExoAppInternal_MainLoop_Hook(CServerExoAppInternal* pApp)
{
    std::vector<InboundMsg> local;
    std::vector<uint32_t> disconnectLocal;
    std::vector<uint32_t> retiredLocal;
    {
        std::lock_guard<std::mutex> lock(g_mtx);
        local.swap(g_inboundQueue);
        disconnectLocal.swap(g_disconnectWsConnId);
        retiredLocal.swap(g_retiredWsConnId);
    }

    const bool result = s_CServerExoAppInternal_MainLoopHook->CallOriginal<BOOL>(pApp);

    g_server_running = !result && pApp->m_nServerMode == 2;

    auto ni = pApp->m_pNetLayer->m_pcNetLayerInternal;

    for (auto& msg : local)
    {
        if (msg.data[0] == 'p')
        {
            uint32_t nSlidingWindow = ~0u;
            ni->ConnectionIdToSlidingWindow(CNetConnectionId(msg.wsConnId), &nSlidingWindow);
            ASSERT(nSlidingWindow != ~0u);
            if (nSlidingWindow == ~0u)
                continue;

            pApp->m_pMessage->HandlePlayerToServerMessage(nSlidingWindow, msg.data.data(),
                static_cast<uint32_t>(msg.data.size()));
        }
        else if (msg.data[0] == 'B')
        {
            auto connId = CNetConnectionId(msg.wsConnId);
            // We have a whitelist of acceptable pre-window messages we receive from
            // the peer. In particular, we never accept crypto handshakes:
            // the WS TLS protection is supposed to handle crypto and protection; also,
            // we don't want custom clients to have to re-implement the crypto layer.
            std::vector<std::string> whitelist = {
                "BNLM", // Ping Request
                "BNLR", // Ping Response
                "BNES", // Discovery
                "BNXI", // Discovery
                "BNDS", // Discovery
                "BNCS", // Auth step 1
                "BNVS", // Auth step 2
                // "BNDM" is not sent by clients; they just close the websocket with a reason.
            };

            if (msg.data.size() < 4 ||
                std::find(whitelist.begin(), whitelist.end(),
                    std::string_view((char*)msg.data.data(), 4)) == whitelist.end())
            {
                LOG_WARNING("Got invalid pre-window message from connId 0x%x; dropping: %.*s",
                    msg.wsConnId, static_cast<int>(msg.data.size()), msg.data.data());
                continue;
            }

            ni->NonWindowMessages(connId, msg.data.data(), static_cast<uint32_t>(msg.data.size()));
        }
        else
        {
            LOG_DEBUG("Got unknown message type '%c' (len=%zu) for connId %u.", msg.data[0],
                msg.data.size(), msg.wsConnId);
        }
    }

    for (auto& connId : disconnectLocal)
    {
        uint32_t nSlidingWindow = ~0u;
        ni->ConnectionIdToSlidingWindow(CNetConnectionId(connId), &nSlidingWindow);
        if (nSlidingWindow != ~0u)
        {
            ni->DisconnectPlayer(nSlidingWindow, 5838u, 0, 0,
                CExoString("WebSocket connection closed"));
        }
        else
        {
            LOG_DEBUG("Disconnect connId 0x%x has invalid slidingWindow; skipping.", connId);
        }
    }

    if (!retiredLocal.empty())
    {
        // Reclaim only after this frame's inbound and disconnect work has been drained,
        // so a recycled ID cannot alias stale queue entries.
        std::lock_guard<std::mutex> lock(g_mtx);
        for (const auto connId : retiredLocal)
        {
            ReleaseWsConnId(connId);
        }
    }

    // Periodic login-timeout scan: kick unauthenticated connections that linger.
    {
        static auto s_lastTimeoutCheck = std::chrono::steady_clock::now();
        static constexpr int TIMEOUT_CHECK_INTERVAL_SECS = 5;

        const auto now = std::chrono::steady_clock::now();
        if (std::chrono::duration_cast<std::chrono::seconds>(now - s_lastTimeoutCheck).count() >=
            TIMEOUT_CHECK_INTERVAL_SECS)
        {
            s_lastTimeoutCheck = now;

            std::lock_guard<std::mutex> lock(g_mtx);
            for (uint32_t i = 0; i < MAX_WS_CONN_IDS; ++i)
            {
                lws* wsi = GetWsiForWsConnId(i + WS_CONN_START_ID);
                if (!wsi)
                    continue;
                auto* d = reinterpret_cast<WSConnUserData*>(lws_wsi_user(wsi));

                if (d && d->playerId == Constants::PLAYERID_INVALIDID)
                {
                    const auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
                        now - d->connectTime)
                                             .count();

                    if (d->gnhi_complete && elapsed > LOGIN_TIMEOUT_SECS)
                    {
                        LOG_INFO(
                            "Login timeout for unauthenticated WS connection connId=0x%x ip=%s.",
                            d->wsConnId, d->ipv4.c_str());
                        d->mustClose = true;
                        d->closeReason = "Authentication timeout";
                        MarkWriteActivity(wsi);
                    }
                }
            }
        }
    }

    return result;
}

//
// LWS service thread — runs until g_lws_running is cleared.
//
static void LWSThreadFunc()
{
    LOG_DEBUG("lws service thread started.");
    while (g_lws_running.load(std::memory_order_relaxed))
        lws_service(g_lws_context, 0);
    LOG_DEBUG("lws service thread stopped.");
}

static BOOL InitWSNetLAyer(CServerExoAppInternal* pApp)
{
    const uint16_t wsDefaultPort = pApp->m_pNetLayer->GetUDPPort();
    ASSERT(wsDefaultPort && wsDefaultPort != 0xFFFF);
    const uint16_t wsPort = static_cast<uint16_t>(Config::Get<int>("PORT", wsDefaultPort));

    {
        std::lock_guard<std::mutex> lock(g_mtx);
        ResetWsConnIdPool();
    }

    const static lws_protocols protocols[] = {
        { "nwn-ws", ws_callback, sizeof(WSConnUserData), 0, 0, nullptr, 0 },
        { nullptr,  nullptr,     0,                      0, 0, nullptr, 0 }
    };

    const static lws_extension extensions[] = {
        { "deflate-frame", lws_extension_callback_pm_deflate,
         "permessage-deflate; client_max_window_bits"                 },
        { nullptr,         nullptr,                           nullptr }
    };

    lws_context_creation_info info {};
    info.port = wsPort;
    info.options = LWS_SERVER_OPTION_DISABLE_IPV6;
    info.protocols = protocols;
    info.extensions = extensions;
    static const lws_retry_bo_t my_idle_policy = {
        .retry_ms_table = nullptr,
        .retry_ms_table_count = 0,
        .conceal_count = 0,
        .secs_since_valid_ping = 5,
        .secs_since_valid_hangup = 60,
        .jitter_percent = 0,
    };
    info.retry_and_idle_policy = &my_idle_policy;

    g_lws_context = lws_create_context(&info);
    if (!g_lws_context)
    {
        LOG_ERROR("Failed to create libwebsockets context on port %u.", wsPort);
        return FALSE;
    }

    LOG_INFO("WebSocket server listening on port %u.", wsPort);

    g_lws_running.store(true, std::memory_order_relaxed);
    g_lws_thread = std::thread(LWSThreadFunc);

    s_CServerExoAppInternal_MainLoopHook = Hooks::HookFunction(&CServerExoAppInternal::MainLoop,
        &CServerExoAppInternal_MainLoop_Hook, Hooks::Order::Default);

    s_CNetLayerInternal_SendMessageToPlayerHook = Hooks::HookFunction(
        &CNetLayerInternal::SendMessageToPlayer, &CNetLayerInternal_SendMessageToPlayer_Hook,
        Hooks::Order::Default);

    s_CNetLayerInternal_SetPlayerConnectedHook = Hooks::HookFunction(
        &CNetLayerInternal::SetPlayerConnected, &CNetLayerInternal_SetPlayerConnected_Hook,
        Hooks::Order::Default);

    s_CNetLayerInternal_DisconnectPlayerHook = Hooks::HookFunction(
        &CNetLayerInternal::DisconnectPlayer, &CNetLayerInternal_DisconnectPlayer_Hook,
        Hooks::Order::Default);

    s_CNetLayerInternal_SendDirectMessageHook = Hooks::HookFunction(
        &CNetLayerInternal::SendDirectMessage, &CNetLayerInternal_SendDirectMessage_Hook,
        Hooks::Order::Default);

    s_CNetLayerInternal_GetPlayerAddressHook = Hooks::HookFunction(
        &CNetLayerInternal::GetPlayerAddress, &CNetLayerInternal_GetPlayerAddress_Hook,
        Hooks::Order::Default);

    s_CNetLayerInternal_GetPlayerAddressDataHook = Hooks::HookFunction(
        &CNetLayerInternal::GetPlayerAddressData, &CNetLayerInternal_GetPlayerAddressData_Hook,
        Hooks::Order::Default);

    s_CExoNetInternal_GetNetworkAddressStringHook = Hooks::HookFunction(
        &CExoNetInternal::GetNetworkAddressString, &CExoNetInternal_GetNetworkAddressString_Hook,
        Hooks::Order::Default);

    s_CExoNetInternal_GetCryptoStateForConnectionHook = Hooks::HookFunction(
        &CExoNetInternal::GetCryptoStateForConnection,
        &CExoNetInternal_GetCryptoStateForConnection_Hook, Hooks::Order::Default);

    s_CNetLayerWindow_FrameTimeout = Hooks::HookFunction(&CNetLayerWindow::FrameTimeout,
        CNetLayerWindow_FrameTimeout_Hook, Hooks::Order::Default);

    // Unhook, init only runs once.
    s_CServerExoAppInternal_MainLoopHook_Init = nullptr;
    return TRUE;
}

static void WSNetLayerCtor() __attribute__((constructor));
static void WSNetLayerCtor()
{
    CExoString* pBuildNumber = Globals::BuildNumber();
    CExoString* pBuildRevision = Globals::BuildRevision();
    CExoString* pBuildPostfix = Globals::BuildPostfix();

    if (*pBuildNumber != "8193" && *pBuildRevision != "37" && *pBuildPostfix != "17")
    {
        // This plugin was *not* tested against earlier or later builds. It uses
        // a lot of internal functions and depends on intrinsic behaviour that may
        // expose you to security issues if you run it on a unverified build.
        // Unhook this check at your own peril.
        LOG_ERROR("Will not load on this version.");
        return;
    }

    //
    // Initialisation happens after the main UDP port was configured.
    //
    s_CServerExoAppInternal_MainLoopHook_Init = Hooks::HookFunction(
        &CServerExoAppInternal::MainLoop, &InitWSNetLAyer, Hooks::Order::Earliest);
}

static void WSNetLayerDtor() __attribute__((destructor));
static void WSNetLayerDtor()
{
    if (g_lws_context)
    {
        g_lws_running.store(false, std::memory_order_relaxed);
        lws_cancel_service(g_lws_context);
        if (g_lws_thread.joinable())
            g_lws_thread.join();
        lws_context_destroy(g_lws_context);
        g_lws_context = nullptr;
    }
}

NWNX_EXPORT int IsWSClient(ArgumentStack&& args)
{
    const auto objectId = args.extract<ObjectID>();
    ASSERT_OR_THROW(objectId != Constants::OBJECT_INVALID);
    const auto playerId = g_pAppManager->m_pServerExoApp->GetPlayerIDByGameObjectID(objectId);
    ASSERT_OR_THROW(playerId != Constants::PLAYERID_INVALIDID);

    std::lock_guard<std::mutex> lock(g_mtx);

    for (uint32_t i = 0; i < MAX_WS_CONN_IDS; ++i)
    {
        lws* wsi = GetWsiForWsConnId(i + WS_CONN_START_ID);
        auto* d = reinterpret_cast<WSConnUserData*>(lws_wsi_user(wsi));
        if (d->playerId == playerId)
            return 1;
    }
    return 0;
}
