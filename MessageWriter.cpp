#include "WSNetLayer.hpp"

// clang-format off
#include "nwnx.hpp"
#include "API/CNWMessage.hpp"
#include "API/CNWSMessage.hpp"
#include "API/CExoLocString.hpp"
// clang-format on

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <string>

using namespace NWNXLib;
using namespace NWNXLib::API;

static MessageFragBuffer s_write_buffer;
static uint8_t* s_last_write_ptr = nullptr;
static uint32_t s_last_write_size = 0;
static bool s_suppress_sub_write = false;

MessageFragBuffer& GetCurrentWriteBuffer()
{ return s_write_buffer; }

uint8_t* GetLastWritePtr()
{ return s_last_write_ptr; }

uint32_t GetLastWriteSize()
{ return s_last_write_size; }

static void WriterCtor() __attribute__((constructor));
static void WriterCtor()
{
    static Hooks::Hook hook_CreateWriteMessage;
    static Hooks::Hook hook_GetWriteMessage;

    // WriteBits: Don't need to hook: the original call consumer is fine with it,
    // and the WS protocol doesn't use it (there is exactly ONE external Read/WriteBits
    //  call in the codebase, and it's a useless canary value (in Input_Attack)).
    static Hooks::Hook hook_WriteBOOL;
    static Hooks::Hook hook_WriteBYTE;
    static Hooks::Hook hook_WriteCHAR;
    static Hooks::Hook hook_WriteWORD;
    static Hooks::Hook hook_WriteSHORT;
    static Hooks::Hook hook_WriteDWORD;
    static Hooks::Hook hook_WriteINT;
    static Hooks::Hook hook_WriteDWORD64;
    static Hooks::Hook hook_WriteINT64;
    static Hooks::Hook hook_WriteFLOAT;
    static Hooks::Hook hook_WriteFLOAT_ranged;
    static Hooks::Hook hook_WriteDOUBLE;
    static Hooks::Hook hook_WriteDOUBLE_ranged;
    static Hooks::Hook hook_WriteCResRef;
    static Hooks::Hook hook_WriteCExoString;
    static Hooks::Hook hook_WriteVOIDPtr;
    static Hooks::Hook hook_WriteJSON;
    static Hooks::Hook hook_WriteOBJECTIDServer;
    static Hooks::Hook hook_WriteCExoLocStringServer;

    hook_CreateWriteMessage = Hooks::HookFunction(
        &CNWMessage::CreateWriteMessage,
        +[](CNWMessage* p, uint32_t nSize, uint32_t dwPlayerID, BOOL bHighPriority) -> void
        {
            s_write_buffer.clear();
            s_suppress_sub_write = true;
            hook_CreateWriteMessage->CallOriginal<void>(p, nSize, dwPlayerID, bHighPriority);
            s_suppress_sub_write = false;
        },
        Hooks::Order::Default);

    hook_GetWriteMessage = Hooks::HookFunction(
        &CNWMessage::GetWriteMessage,
        +[](CNWMessage* p, uint8_t** pMessage, uint32_t* dwSize) -> BOOL
        {
            auto result = hook_GetWriteMessage->CallOriginal<BOOL>(p, pMessage, dwSize);
            s_last_write_ptr = *pMessage;
            s_last_write_size = *dwSize;
            return result;
        },
        Hooks::Order::Default);

    hook_WriteBOOL = Hooks::HookFunction(
        &CNWMessage::WriteBOOL,
        +[](CNWMessage* p, BOOL b) -> void
        {
            const bool was_suppressed = s_suppress_sub_write;
            s_suppress_sub_write = true;
            hook_WriteBOOL->CallOriginal<void>(p, b);
            s_suppress_sub_write = was_suppressed;

            if (!was_suppressed)
            {
                s_write_buffer.push_back({ WSMsgType::BOOL, static_cast<uint64_t>(b) });
            }
        },
        Hooks::Order::Default);

    hook_WriteBYTE = Hooks::HookFunction(
        &CNWMessage::WriteBYTE,
        +[](CNWMessage* p, uint8_t nByte, int32_t nCount, BOOL bPrefix) -> void
        {
            const bool was_suppressed = s_suppress_sub_write;
            s_suppress_sub_write = true;
            hook_WriteBYTE->CallOriginal<void>(p, nByte, nCount, bPrefix);
            s_suppress_sub_write = was_suppressed;

            if (!was_suppressed)
            {
                s_write_buffer.push_back({ WSMsgType::BYTE, static_cast<uint64_t>(nByte) });
            }
        },
        Hooks::Order::Default);

    hook_WriteCHAR = Hooks::HookFunction(
        &CNWMessage::WriteCHAR,
        +[](CNWMessage* p, char nChar, int32_t nCount) -> void
        {
            const bool was_suppressed = s_suppress_sub_write;
            s_suppress_sub_write = true;
            hook_WriteCHAR->CallOriginal<void>(p, nChar, nCount);
            s_suppress_sub_write = was_suppressed;

            if (!was_suppressed)
            {
                s_write_buffer.push_back(
                    { WSMsgType::CHAR, static_cast<uint64_t>(static_cast<uint8_t>(nChar)) });
            }
        },
        Hooks::Order::Default);

    hook_WriteWORD = Hooks::HookFunction(
        &CNWMessage::WriteWORD,
        +[](CNWMessage* p, uint16_t nWord, int32_t nCount) -> void
        {
            const bool was_suppressed = s_suppress_sub_write;
            s_suppress_sub_write = true;
            hook_WriteWORD->CallOriginal<void>(p, nWord, nCount);
            s_suppress_sub_write = was_suppressed;

            if (!was_suppressed)
            {
                s_write_buffer.push_back({ WSMsgType::WORD, static_cast<uint64_t>(nWord) });
            }
        },
        Hooks::Order::Default);

    hook_WriteSHORT = Hooks::HookFunction(
        &CNWMessage::WriteSHORT,
        +[](CNWMessage* p, int16_t nShort, int32_t nCount) -> void
        {
            const bool was_suppressed = s_suppress_sub_write;
            s_suppress_sub_write = true;
            hook_WriteSHORT->CallOriginal<void>(p, nShort, nCount);
            s_suppress_sub_write = was_suppressed;

            if (!was_suppressed)
            {
                s_write_buffer.push_back(
                    { WSMsgType::SHORT, static_cast<uint64_t>(static_cast<uint16_t>(nShort)) });
            }
        },
        Hooks::Order::Default);

    hook_WriteDWORD = Hooks::HookFunction(
        &CNWMessage::WriteDWORD,
        +[](CNWMessage* p, uint32_t nDword, int32_t nCount) -> void
        {
            const bool was_suppressed = s_suppress_sub_write;
            s_suppress_sub_write = true;
            hook_WriteDWORD->CallOriginal<void>(p, nDword, nCount);
            s_suppress_sub_write = was_suppressed;

            if (!was_suppressed)
            {
                s_write_buffer.push_back({ WSMsgType::DWORD, static_cast<uint64_t>(nDword) });
            }
        },
        Hooks::Order::Default);

    hook_WriteINT = Hooks::HookFunction(
        &CNWMessage::WriteINT,
        +[](CNWMessage* p, int32_t nInteger, int32_t nCount) -> void
        {
            const bool was_suppressed = s_suppress_sub_write;
            s_suppress_sub_write = true;
            hook_WriteINT->CallOriginal<void>(p, nInteger, nCount);
            s_suppress_sub_write = was_suppressed;

            if (!was_suppressed)
            {
                s_write_buffer.push_back(
                    { WSMsgType::INT, static_cast<uint64_t>(static_cast<uint32_t>(nInteger)) });
            }
        },
        Hooks::Order::Default);

    hook_WriteDWORD64 = Hooks::HookFunction(
        &CNWMessage::WriteDWORD64,
        +[](CNWMessage* p, uint64_t nDword64, int32_t nCount) -> void
        {
            const bool was_suppressed = s_suppress_sub_write;
            s_suppress_sub_write = true;
            hook_WriteDWORD64->CallOriginal<void>(p, nDword64, nCount);
            s_suppress_sub_write = was_suppressed;

            if (!was_suppressed)
            {
                s_write_buffer.push_back({ WSMsgType::DWORD64, nDword64 });
            }
        },
        Hooks::Order::Default);

    hook_WriteINT64 = Hooks::HookFunction(
        &CNWMessage::WriteINT64,
        +[](CNWMessage* p, int64_t nInt64, int32_t nCount) -> void
        {
            const bool was_suppressed = s_suppress_sub_write;
            s_suppress_sub_write = true;
            hook_WriteINT64->CallOriginal<void>(p, nInt64, nCount);
            s_suppress_sub_write = was_suppressed;

            if (!was_suppressed)
            {
                s_write_buffer.push_back({ WSMsgType::INT64, static_cast<uint64_t>(nInt64) });
            }
        },
        Hooks::Order::Default);

    hook_WriteFLOAT = Hooks::HookFunction(
        static_cast<void (CNWMessage::*)(float, float, int32_t)>(&CNWMessage::WriteFLOAT),
        +[](CNWMessage* p, float fFloat, float fMultiplier, int32_t nCount) -> void
        {
            const bool was_suppressed = s_suppress_sub_write;
            s_suppress_sub_write = true;
            hook_WriteFLOAT->CallOriginal<void>(p, fFloat, fMultiplier, nCount);
            s_suppress_sub_write = was_suppressed;

            if (!was_suppressed)
            {
                s_write_buffer.push_back({ WSMsgType::FLOAT, bitcast<uint32_t>(fFloat) });
            }
        },
        Hooks::Order::Default);

    hook_WriteFLOAT_ranged = Hooks::HookFunction(
        static_cast<void (CNWMessage::*)(float, float, float, int32_t)>(&CNWMessage::WriteFLOAT),
        +[](CNWMessage* p, float fFloat, float fMin, float fMax, int32_t nCount) -> void
        {
            const bool was_suppressed = s_suppress_sub_write;
            s_suppress_sub_write = true;
            hook_WriteFLOAT_ranged->CallOriginal<void>(p, fFloat, fMin, fMax, nCount);
            s_suppress_sub_write = was_suppressed;

            if (!was_suppressed)
            {
                s_write_buffer.push_back(
                    { WSMsgType::FLOAT, bitcast<uint32_t>(std::clamp(fFloat, fMin, fMax)) });
            }
        },
        Hooks::Order::Default);

    hook_WriteDOUBLE = Hooks::HookFunction(
        static_cast<void (CNWMessage::*)(double, double, int32_t)>(&CNWMessage::WriteDOUBLE),
        +[](CNWMessage* p, double fDouble, double fMultiplier, int32_t nCount) -> void
        {
            const bool was_suppressed = s_suppress_sub_write;
            s_suppress_sub_write = true;
            hook_WriteDOUBLE->CallOriginal<void>(p, fDouble, fMultiplier, nCount);
            s_suppress_sub_write = was_suppressed;

            if (!was_suppressed)
            {
                s_write_buffer.push_back({ WSMsgType::DOUBLE, bitcast<uint64_t>(fDouble) });
            }
        },
        Hooks::Order::Default);

    hook_WriteDOUBLE_ranged = Hooks::HookFunction(
        static_cast<void (CNWMessage::*)(double, double, double, int32_t)>(
            &CNWMessage::WriteDOUBLE),
        +[](CNWMessage* p, double fDouble, double fMin, double fMax, int32_t nCount) -> void
        {
            const bool was_suppressed = s_suppress_sub_write;
            s_suppress_sub_write = true;
            hook_WriteDOUBLE_ranged->CallOriginal<void>(p, fDouble, fMin, fMax, nCount);
            s_suppress_sub_write = was_suppressed;

            if (!was_suppressed)
            {
                s_write_buffer.push_back(
                    { WSMsgType::DOUBLE, bitcast<uint64_t>(std::clamp(fDouble, fMin, fMax)) });
            }
        },
        Hooks::Order::Default);

    hook_WriteCResRef = Hooks::HookFunction(
        &CNWMessage::WriteCResRef,
        +[](CNWMessage* p, CResRef resRef, int32_t nCount) -> void
        {
            const bool was_suppressed = s_suppress_sub_write;
            s_suppress_sub_write = true;
            hook_WriteCResRef->CallOriginal<void>(p, resRef, nCount);
            s_suppress_sub_write = was_suppressed;

            if (!was_suppressed)
            {
                s_write_buffer.push_back(
                    { WSMsgType::RESREF, 0, std::string(resRef.GetResRefStr()) });
            }
        },
        Hooks::Order::Default);

    hook_WriteCExoString = Hooks::HookFunction(
        &CNWMessage::WriteCExoString,
        +[](CNWMessage* p, CExoString sString, int32_t nCount) -> void
        {
            const bool was_suppressed = s_suppress_sub_write;
            s_suppress_sub_write = true;
            hook_WriteCExoString->CallOriginal<void>(p, sString, nCount);
            s_suppress_sub_write = was_suppressed;

            if (!was_suppressed)
            {
                s_write_buffer.push_back(
                    { WSMsgType::STRING, 0, std::string(sString.CStr(), sString.GetLength()) });
            }
        },
        Hooks::Order::Default);

    hook_WriteVOIDPtr = Hooks::HookFunction(
        &CNWMessage::WriteVOIDPtr,
        +[](CNWMessage* p, void* pVoidPtr, int32_t nSize) -> void
        {
            const bool was_suppressed = s_suppress_sub_write;
            s_suppress_sub_write = true;
            hook_WriteVOIDPtr->CallOriginal<void>(p, pVoidPtr, nSize);
            s_suppress_sub_write = was_suppressed;

            if (!was_suppressed)
            {
                MessageFrag f;
                f.t = WSMsgType::VOIDPTR;
                f.data = std::string(static_cast<const char*>(pVoidPtr), nSize);
                s_write_buffer.push_back(std::move(f));
            }
        },
        Hooks::Order::Default);

    hook_WriteJSON = Hooks::HookFunction(
        &CNWMessage::WriteJSON,
        +[](CNWMessage* p, const json& j) -> void
        {
            const bool was_suppressed = s_suppress_sub_write;
            s_suppress_sub_write = true;
            hook_WriteJSON->CallOriginal<void>(p, j);
            s_suppress_sub_write = was_suppressed;

            if (!was_suppressed)
            {
                MessageFrag f;
                f.t = WSMsgType::JSON;
                f.data = j.dump();
                s_write_buffer.push_back(std::move(f));
            }
        },
        Hooks::Order::Default);

    hook_WriteOBJECTIDServer = Hooks::HookFunction(
        &CNWSMessage::WriteOBJECTIDServer,
        +[](CNWSMessage* p, OBJECT_ID nObjID) -> void
        {
            // NB: We send serverside OIDs. Client OIDs are not meaningful to WS peers.
            s_write_buffer.push_back({ WSMsgType::OBJECT_ID, static_cast<uint64_t>(nObjID) });

            hook_WriteOBJECTIDServer->CallOriginal<void>(p, nObjID);
        },
        Hooks::Order::Default);

    hook_WriteCExoLocStringServer = Hooks::HookFunction(
        &CNWSMessage::WriteCExoLocStringServer,
        +[](CNWSMessage* p, const CExoLocString& sLocString, uint8_t nGender) -> void
        {
            // WriteCExoLocStringServer internally calls WriteBOOL + WriteBYTE/WriteDWORD or
            // WriteBOOL + WriteCExoString.  We capture those sub-frags and collapse them into
            // a single LOCSTRING frag so the consumer sees one typed field.
            const size_t start = s_write_buffer.size();

            hook_WriteCExoLocStringServer->CallOriginal<void>(p, sLocString, nGender);

            // Collect sub-frags and erase them.
            MessageFragBuffer sub(s_write_buffer.begin() + start, s_write_buffer.end());
            s_write_buffer.erase(s_write_buffer.begin() + start, s_write_buffer.end());

            MessageFrag lf;
            lf.t = WSMsgType::LOCSTRING;

            if (!sub.empty() && sub[0].t == WSMsgType::BOOL && sub[0].value != 0)
            {
                // StrRef path:  BOOL(1), BYTE(gender), DWORD(strref)
                const uint8_t gender = sub.size() >= 2 ? static_cast<uint8_t>(sub[1].value) : 0;
                const uint32_t strref = sub.size() >= 3 ? static_cast<uint32_t>(sub[2].value) : 0;
                lf.value = static_cast<uint64_t>(strref) | (static_cast<uint64_t>(gender) << 32) |
                    (1ULL << 63);
            }
            else
            {
                // String path: BOOL(0), STRING(text)
                if (sub.size() >= 2 && sub[1].t == WSMsgType::STRING)
                    lf.data = sub[1].data;
            }

            s_write_buffer.push_back(std::move(lf));
        },
        Hooks::Order::Default);
}
