#include "WSNetLayer.hpp"

// clang-format off
#include "nwn_api.hpp"
#include "nwnx.hpp"
#include "API/CAppManager.hpp"
#include "API/CServerExoApp.hpp"
#include "API/CNetLayer.hpp"
#include "API/CNWMessage.hpp"
#include "API/CNWSMessage.hpp"
// clang-format on

#include <algorithm>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <string>

using namespace NWNXLib;
using namespace NWNXLib::API;

static bool s_in_ws_handler = false;
static size_t s_stream_pos = 0;
static MessageFragBuffer s_read_buffer;

// Mask an unsigned value to nCount bits (no-op when nCount >= fullbits).
static uint64_t mask_to_nbits(uint64_t v, int32_t nCount, int32_t fullbits)
{
    if (nCount <= 0 || nCount >= fullbits)
        return v;
    return v & ((uint64_t(1) << nCount) - 1);
}

// Clamp a signed value to the two's-complement range of nCount bits (no-op when nCount >=
// fullbits).
static int64_t clamp_to_nbits_signed(int64_t v, int32_t nCount, int32_t fullbits)
{
    if (nCount <= 0 || nCount >= fullbits)
        return v;
    const int64_t maxv = (int64_t(1) << (nCount - 1)) - 1;
    const int64_t minv = -(int64_t(1) << (nCount - 1));
    return std::clamp(v, minv, maxv);
}

static const char* FragTypeName(WSMsgType t)
{
    switch (t)
    {
        case WSMsgType::BITS:      return "BITS";
        case WSMsgType::BOOL:      return "BOOL";
        case WSMsgType::BYTE:      return "BYTE";
        case WSMsgType::CHAR:      return "CHAR";
        case WSMsgType::WORD:      return "WORD";
        case WSMsgType::SHORT:     return "SHORT";
        case WSMsgType::DWORD:     return "DWORD";
        case WSMsgType::INT:       return "INT";
        case WSMsgType::DWORD64:   return "DWORD64";
        case WSMsgType::INT64:     return "INT64";
        case WSMsgType::FLOAT:     return "FLOAT";
        case WSMsgType::DOUBLE:    return "DOUBLE";
        case WSMsgType::RESREF:    return "RESREF";
        case WSMsgType::STRING:    return "STRING";
        case WSMsgType::VOIDPTR:   return "VOIDPTR";
        case WSMsgType::JSON:      return "JSON";
        case WSMsgType::OBJECT_ID: return "OBJECT_ID";
        case WSMsgType::LOCSTRING: return "LOCSTRING";
        default:                   return "?";
    }
}

static void ReportDesync(WSMsgType expected, const MessageFrag& got)
{
    // Build a short lookahead of remaining types for context (up to 16).
    std::string remaining;
    size_t shown = 0;
    for (const auto& f : s_read_buffer)
    {
        if (shown++)
            remaining += ' ';
        remaining += FragTypeName(f.t);
        if (shown >= 16)
        {
            remaining += " ...";
            break;
        }
    }

    const size_t preview_len = std::min(got.data.size(), size_t(64));
    LOG_ERROR(
        "WSNetLayer desync at stream pos %zu: expected %s, got %s "
        "(value=0x%016llx, data=%zu bytes: \"%.*s\"%s); "
        "next frags: [%s]",
        s_stream_pos, FragTypeName(expected), FragTypeName(got.t),
        static_cast<unsigned long long>(got.value), got.data.size(), static_cast<int>(preview_len),
        got.data.data(), got.data.size() > 64 ? "..." : "",
        remaining.empty() ? "(empty)" : remaining.c_str());
}

static bool PopFrag(WSMsgType expected, MessageFrag& out)
{
    if (s_read_buffer.empty())
    {
        MessageFrag sentinel;
        sentinel.t = static_cast<WSMsgType>(0);
        LOG_ERROR("WSNetLayer desync at stream pos %zu: expected %s but buffer is empty.",
            s_stream_pos, FragTypeName(expected));
        out = sentinel;
        return false;
    }

    out = s_read_buffer.front();
    s_read_buffer.pop_front();
    ++s_stream_pos;

    if (out.t != expected)
    {
        ReportDesync(expected, out);
        return false;
    }
    return true;
}

static void ReaderCtor() __attribute__((constructor));
static void ReaderCtor()
{
    static Hooks::Hook hook_HandlePlayerToServerMessage;
    static Hooks::Hook hook_SetReadMessage;

    static Hooks::Hook hook_ReadBITS;
    static Hooks::Hook hook_ReadBOOL;
    static Hooks::Hook hook_ReadBYTE;
    static Hooks::Hook hook_ReadCHAR;
    static Hooks::Hook hook_ReadWORD;
    static Hooks::Hook hook_ReadSHORT;
    static Hooks::Hook hook_ReadDWORD;
    static Hooks::Hook hook_ReadINT;
    static Hooks::Hook hook_ReadDWORD64;
    static Hooks::Hook hook_ReadINT64;
    static Hooks::Hook hook_ReadFLOAT;
    static Hooks::Hook hook_ReadFLOAT_ranged;
    static Hooks::Hook hook_ReadDOUBLE;
    static Hooks::Hook hook_ReadDOUBLE_ranged;
    static Hooks::Hook hook_ReadCResRef;
    static Hooks::Hook hook_ReadCExoString;
    static Hooks::Hook hook_ReadVOIDPtr;
    static Hooks::Hook hook_ReadJSON;
    static Hooks::Hook hook_ReadOBJECTIDServer;

    // Other plugins look at a message before the engine's handler reads it by making the
    // same Read* calls inside a Utils::MessagePeek, and throw a message away with
    // Utils::ClearReadMessage. Neither can reach our read state on its own, since it is
    // not the engine's read buffer: a peek's reads pop our fragments like any others.
    // So a peek saves the fragment queue and puts it back when it ends, and a clear
    // empties it. Outside a WS message there is nothing of ours to save.
    // (niv/NWNX_WSNetLayer#3: before this, peeks read the engine's buffer directly,
    // which a WS message never sets, and crashed on what the last UDP message left.)
    Utils::RegisterMessageReadHandler({
        [](CNWSMessage*) -> std::function<void()>
        {
            if (!s_in_ws_handler)
                return {};

            return [saved = s_read_buffer, pos = s_stream_pos]()
            {
                s_read_buffer = saved;
                s_stream_pos = pos;
            };
        },
        [](CNWSMessage*)
        {
            if (s_in_ws_handler)
                s_read_buffer.clear();
        },
    });

    hook_HandlePlayerToServerMessage = Hooks::HookFunction(
        &CNWSMessage::HandlePlayerToServerMessage,
        +[](CNWSMessage* p, uint32_t nPlayerId, uint8_t* pBuffer, uint32_t nBufferSize) -> void
        {
            CNetConnectionId connId;
            const bool is_ws = g_pAppManager->m_pServerExoApp->GetNetLayer()
                                   ->PlayerIdToConnectionId(nPlayerId, &connId) &&
                IsValidWsConnId(*connId);

            if (is_ws)
            {
                if (nBufferSize < 3)
                {
                    LOG_ERROR("WS message too short to read header from playerId=0x%08x; dropping.",
                        nPlayerId);
                    return;
                }

                try
                {
                    s_read_buffer = DeserializeWireToFragBuffer(pBuffer + 3, nBufferSize - 3);
                }
                catch (const FragReadOverrun&)
                {
                    LOG_ERROR(
                        "WS message from playerId=0x%08x is truncated or malformed; dropping.",
                        nPlayerId);
                    s_read_buffer.clear();
                    return;
                }
                s_stream_pos = 0;
                // NB: A empty buffer is entirely acceptable; some messages have no payload at all.
                s_in_ws_handler = true;
            }

            hook_HandlePlayerToServerMessage->CallOriginal<void>(p, nPlayerId, pBuffer,
                nBufferSize);
            s_in_ws_handler = false;
        },
        Hooks::Order::Default);

    hook_SetReadMessage = Hooks::HookFunction(
        &CNWMessage::SetReadMessage,
        +[](CNWMessage* p, uint8_t* pMessage, uint32_t dwSize, uint32_t dwPlayerID,
             BOOL bHighPriority) -> BOOL
        {
            if (!s_in_ws_handler)
            {
                return hook_SetReadMessage->CallOriginal<BOOL>(p, pMessage, dwSize, dwPlayerID,
                    bHighPriority);
            }

            // Never set the read message for the WS reader; we fully tablecloth it.
            return TRUE;
        },
        Hooks::Order::Default);

    hook_ReadBITS = Hooks::HookFunction(
        &CNWMessage::ReadBits,
        +[](CNWMessage* p, int32_t nCount) -> int64_t
        {
            if (!s_in_ws_handler)
                return hook_ReadBITS->CallOriginal<int64_t>(p, nCount);
            LOG_ERROR(
                "WSNetLayer: ReadBits called in WS handler at stream pos %zu. "
                "This should never have happened.",
                s_stream_pos);
            return 0;
        },
        Hooks::Order::Default);

    hook_ReadBOOL = Hooks::HookFunction(
        &CNWMessage::ReadBOOL,
        +[](CNWMessage* p) -> BOOL
        {
            if (!s_in_ws_handler)
                return hook_ReadBOOL->CallOriginal<BOOL>(p);
            MessageFrag f;
            if (!PopFrag(WSMsgType::BOOL, f))
                return FALSE;
            return static_cast<BOOL>(f.value);
        },
        Hooks::Order::Default);

    hook_ReadBYTE = Hooks::HookFunction(
        &CNWMessage::ReadBYTE,
        +[](CNWMessage* p, int32_t nCount, BOOL bPrefix) -> uint8_t
        {
            if (!s_in_ws_handler)
                return hook_ReadBYTE->CallOriginal<uint8_t>(p, nCount, bPrefix);
            MessageFrag f;
            if (!PopFrag(WSMsgType::BYTE, f))
                return 0;
            return static_cast<uint8_t>(mask_to_nbits(f.value, nCount, 8));
        },
        Hooks::Order::Default);

    hook_ReadCHAR = Hooks::HookFunction(
        &CNWMessage::ReadCHAR,
        +[](CNWMessage* p, int32_t nCount) -> char
        {
            if (!s_in_ws_handler)
                return hook_ReadCHAR->CallOriginal<char>(p, nCount);
            MessageFrag f;
            if (!PopFrag(WSMsgType::CHAR, f))
                return 0;
            const int8_t raw = static_cast<int8_t>(static_cast<uint8_t>(f.value));
            return static_cast<char>(clamp_to_nbits_signed(raw, nCount, 8));
        },
        Hooks::Order::Default);

    hook_ReadWORD = Hooks::HookFunction(
        &CNWMessage::ReadWORD,
        +[](CNWMessage* p, int32_t nCount) -> uint16_t
        {
            if (!s_in_ws_handler)
                return hook_ReadWORD->CallOriginal<uint16_t>(p, nCount);
            MessageFrag f;
            if (!PopFrag(WSMsgType::WORD, f))
                return 0;
            return static_cast<uint16_t>(mask_to_nbits(f.value, nCount, 16));
        },
        Hooks::Order::Default);

    hook_ReadSHORT = Hooks::HookFunction(
        &CNWMessage::ReadSHORT,
        +[](CNWMessage* p, int32_t nCount) -> int16_t
        {
            if (!s_in_ws_handler)
                return hook_ReadSHORT->CallOriginal<int16_t>(p, nCount);
            MessageFrag f;
            if (!PopFrag(WSMsgType::SHORT, f))
                return 0;
            const int16_t raw = static_cast<int16_t>(static_cast<uint16_t>(f.value));
            return static_cast<int16_t>(clamp_to_nbits_signed(raw, nCount, 16));
        },
        Hooks::Order::Default);

    hook_ReadDWORD = Hooks::HookFunction(
        &CNWMessage::ReadDWORD,
        +[](CNWMessage* p, int32_t nCount) -> uint32_t
        {
            if (!s_in_ws_handler)
                return hook_ReadDWORD->CallOriginal<uint32_t>(p, nCount);
            MessageFrag f;
            if (!PopFrag(WSMsgType::DWORD, f))
                return 0;
            return static_cast<uint32_t>(mask_to_nbits(f.value, nCount, 32));
        },
        Hooks::Order::Default);

    hook_ReadINT = Hooks::HookFunction(
        &CNWMessage::ReadINT,
        +[](CNWMessage* p, int32_t nCount) -> int32_t
        {
            if (!s_in_ws_handler)
                return hook_ReadINT->CallOriginal<int32_t>(p, nCount);
            MessageFrag f;
            if (!PopFrag(WSMsgType::INT, f))
                return 0;
            const int32_t raw = static_cast<int32_t>(static_cast<uint32_t>(f.value));
            return static_cast<int32_t>(clamp_to_nbits_signed(raw, nCount, 32));
        },
        Hooks::Order::Default);

    hook_ReadDWORD64 = Hooks::HookFunction(
        &CNWMessage::ReadDWORD64,
        +[](CNWMessage* p, int32_t nCount) -> uint64_t
        {
            if (!s_in_ws_handler)
                return hook_ReadDWORD64->CallOriginal<uint64_t>(p, nCount);
            MessageFrag f;
            if (!PopFrag(WSMsgType::DWORD64, f))
                return 0;
            return mask_to_nbits(f.value, nCount, 64);
        },
        Hooks::Order::Default);

    hook_ReadINT64 = Hooks::HookFunction(
        &CNWMessage::ReadINT64,
        +[](CNWMessage* p, int32_t nCount) -> int64_t
        {
            if (!s_in_ws_handler)
                return hook_ReadINT64->CallOriginal<int64_t>(p, nCount);
            MessageFrag f;
            if (!PopFrag(WSMsgType::INT64, f))
                return 0;
            return static_cast<int64_t>(
                clamp_to_nbits_signed(static_cast<int64_t>(f.value), nCount, 64));
        },
        Hooks::Order::Default);

    hook_ReadFLOAT = Hooks::HookFunction(
        static_cast<float (CNWMessage::*)(float, int32_t)>(&CNWMessage::ReadFLOAT),
        +[](CNWMessage* p, float fMultiplier, int32_t nCount) -> float
        {
            if (!s_in_ws_handler)
                return hook_ReadFLOAT->CallOriginal<float>(p, fMultiplier, nCount);
            MessageFrag f;
            if (!PopFrag(WSMsgType::FLOAT, f))
                return 0.0f;
            return bitcast<float>(static_cast<uint32_t>(f.value));
        },
        Hooks::Order::Default);

    hook_ReadFLOAT_ranged = Hooks::HookFunction(
        static_cast<float (CNWMessage::*)(float, float, int32_t)>(&CNWMessage::ReadFLOAT),
        +[](CNWMessage* p, float fMin, float fMax, int32_t nCount) -> float
        {
            if (!s_in_ws_handler)
                return hook_ReadFLOAT_ranged->CallOriginal<float>(p, fMin, fMax, nCount);
            MessageFrag f;
            if (!PopFrag(WSMsgType::FLOAT, f))
                return 0.0f;
            return std::clamp(bitcast<float>(static_cast<uint32_t>(f.value)), fMin, fMax);
        },
        Hooks::Order::Default);

    hook_ReadDOUBLE = Hooks::HookFunction(
        static_cast<double (CNWMessage::*)(double, int32_t)>(&CNWMessage::ReadDOUBLE),
        +[](CNWMessage* p, double fMultiplier, int32_t nCount) -> double
        {
            if (!s_in_ws_handler)
                return hook_ReadDOUBLE->CallOriginal<double>(p, fMultiplier, nCount);
            MessageFrag f;
            if (!PopFrag(WSMsgType::DOUBLE, f))
                return 0.0;
            return bitcast<double>(f.value);
        },
        Hooks::Order::Default);

    hook_ReadDOUBLE_ranged = Hooks::HookFunction(
        static_cast<double (CNWMessage::*)(double, double, int32_t)>(&CNWMessage::ReadDOUBLE),
        +[](CNWMessage* p, double fMin, double fMax, int32_t nCount) -> double
        {
            if (!s_in_ws_handler)
                return hook_ReadDOUBLE_ranged->CallOriginal<double>(p, fMin, fMax, nCount);
            MessageFrag f;
            if (!PopFrag(WSMsgType::DOUBLE, f))
                return 0.0;
            return std::clamp(bitcast<double>(f.value), fMin, fMax);
        },
        Hooks::Order::Default);

    hook_ReadCResRef = Hooks::HookFunction(
        &CNWMessage::ReadCResRef,
        +[](CNWMessage* p, int32_t nCount) -> CResRef
        {
            if (!s_in_ws_handler)
                return hook_ReadCResRef->CallOriginal<CResRef>(p, nCount);
            MessageFrag f;
            if (!PopFrag(WSMsgType::RESREF, f))
                return CResRef {};
            return CResRef { f.data.c_str() };
        },
        Hooks::Order::Default);

    hook_ReadCExoString = Hooks::HookFunction(
        &CNWMessage::ReadCExoString,
        +[](CNWMessage* p, int32_t nCount) -> CExoString
        {
            if (!s_in_ws_handler)
                return hook_ReadCExoString->CallOriginal<CExoString>(p, nCount);
            MessageFrag f;
            if (!PopFrag(WSMsgType::STRING, f))
                return CExoString { "" };
            return CExoString { f.data.c_str(), static_cast<int32_t>(f.data.size()) };
        },
        Hooks::Order::Default);

    hook_ReadVOIDPtr = Hooks::HookFunction(
        &CNWMessage::ReadVOIDPtr,
        +[](CNWMessage* p, int32_t nSize) -> void*
        {
            if (!s_in_ws_handler)
                return hook_ReadVOIDPtr->CallOriginal<void*>(p, nSize);
            MessageFrag f;
            if (!PopFrag(WSMsgType::VOIDPTR, f))
                return nullptr;
            void* buf = std::malloc(f.data.size());
            if (buf)
                std::memcpy(buf, f.data.data(), f.data.size());
            return buf;
        },
        Hooks::Order::Default);

    hook_ReadJSON = Hooks::HookFunction(
        &CNWMessage::ReadJSON,
        +[](CNWMessage* p) -> json
        {
            if (!s_in_ws_handler)
                return hook_ReadJSON->CallOriginal<json>(p);
            MessageFrag f;
            if (!PopFrag(WSMsgType::JSON, f))
                return json {};

            // [TODO] Do we need to catch the exc? What will NWN do with value_t::discarded?
            return json::parse(f.data, nullptr, /*allow_exceptions=*/false);
        },
        Hooks::Order::Default);

    hook_ReadOBJECTIDServer = Hooks::HookFunction(
        &CNWSMessage::ReadOBJECTIDServer,
        +[](CNWSMessage* p) -> OBJECT_ID
        {
            if (!s_in_ws_handler)
                return hook_ReadOBJECTIDServer->CallOriginal<OBJECT_ID>(p);

            MessageFrag f;
            if (!PopFrag(WSMsgType::OBJECT_ID, f))
                return 0;

            // No LISTTYPE_MASK needed: our WS client must send clean server-side OIDs.
            return static_cast<OBJECT_ID>(f.value);
        },
        Hooks::Order::Default);
}
