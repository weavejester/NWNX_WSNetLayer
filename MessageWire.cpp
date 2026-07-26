#include "MessageWire.hpp"
#include "WSNetLayer.hpp"

#include "nwnx.hpp"

#include <cstring>
#include <vector>

using namespace NWNXLib;
using namespace NWNXLib::API;

//
// Wire format for WS client <-> server messages, excluding routing envelope.
//
// Layout:
//   For each frag:
//     [uint8 type]
//     [payload]
//
// Payload encodings (all integers little-endian, no padding):
//   BOOL:    uint8           (0 or 1)
//   BYTE:    uint8
//   CHAR:    uint8           (signed char stored as two's complement)
//   WORD:    uint16
//   SHORT:   uint16          (signed, two's complement)
//   DWORD:   uint32
//   INT:     uint32          (signed, two's complement)
//   DWORD64: uint64
//   INT64:   uint64          (signed, two's complement)
//   FLOAT:   uint32          (raw IEEE 754 bits; full precision, no quantization)
//   DOUBLE:  uint64          (raw IEEE 754 bits; full precision, no quantization)
//   RESREF:  uint8 len + [len bytes]            (no null terminator; max 16 bytes)
//   STRING:  uint32 len + [len bytes]           (UTF-8; no null terminator)
//   VOIDPTR:   uint32 len + [len bytes]
//   JSON:      uint32 len + [len bytes]           (UTF-8 JSON text)
//   OBJECT_ID: uint32                             (same wire width as DWORD; distinct type tag)
//   LOCSTRING: uint8 is_strref
//              + if is_strref: uint8 gender + uint32 strref
//              + else:         uint32 len + [len bytes UTF-8]
//
// BITS is never encoded; encountering it in a write buffer is a bug.
//

std::vector<uint8_t> SerializeFragBufferToWire(MessageFragBuffer& buf)
{
    WireWriter wr;

    for (const auto& f : buf)
    {
        wr.WriteU8(static_cast<uint8_t>(f.t));

        switch (f.t)
        {
            case WSMsgType::BOOL:  wr.WriteU8(static_cast<uint8_t>(f.value & 1)); break;

            case WSMsgType::BYTE:
            case WSMsgType::CHAR:  wr.WriteU8(static_cast<uint8_t>(f.value & 0xFF)); break;

            case WSMsgType::WORD:
            case WSMsgType::SHORT: wr.WriteU16(static_cast<uint16_t>(f.value & 0xFFFF)); break;

            case WSMsgType::DWORD:
            case WSMsgType::INT:   wr.WriteU32(static_cast<uint32_t>(f.value & 0xFFFFFFFF)); break;

            case WSMsgType::OBJECT_ID:
                wr.WriteU32(static_cast<uint32_t>(f.value & 0xFFFFFFFF));
                break;

            case WSMsgType::DWORD64:
            case WSMsgType::INT64:   wr.WriteU64(f.value); break;

            case WSMsgType::FLOAT:   wr.WriteU32(static_cast<uint32_t>(f.value)); break;

            case WSMsgType::DOUBLE:  wr.WriteU64(f.value); break;

            case WSMsgType::RESREF:
            {
                const size_t len = std::min(f.data.size(), size_t(16));
                wr.WriteU8(static_cast<uint8_t>(len));
                wr.WriteBytes(f.data.data(), len);
                break;
            }

            case WSMsgType::STRING:
            case WSMsgType::VOIDPTR:
            case WSMsgType::JSON:
                wr.WriteU32(static_cast<uint32_t>(f.data.size()));
                wr.WriteBytes(f.data.data(), f.data.size());
                break;

            case WSMsgType::LOCSTRING:
                if (f.value & (1ULL << 63))
                {
                    // StrRef: is_strref=1, gender(1), strref(4)
                    wr.WriteU8(0x01);
                    wr.WriteU8(static_cast<uint8_t>((f.value >> 32) & 0xFF));
                    wr.WriteU32(static_cast<uint32_t>(f.value & 0xFFFFFFFF));
                }
                else
                {
                    // String: is_strref=0, len(4), bytes
                    wr.WriteU8(0x00);
                    wr.WriteU32(static_cast<uint32_t>(f.data.size()));
                    wr.WriteBytes(f.data.data(), f.data.size());
                }
                break;

            case WSMsgType::BITS:
                throw ProtocolError("BITS frag in write buffer should never happen; skipping.");

            default: throw ProtocolError("Unknown WsMsgType"); break;
        }
    }

    return wr.data;
}

MessageFragBuffer DeserializeWireToFragBuffer(const uint8_t* data, size_t len)
{
    MessageFragBuffer result;

    WireReader r { data, len };

    size_t i = 0;

    while (!r.at_end())
    {
        const auto t = static_cast<WSMsgType>(r.U8());

        MessageFrag f;
        f.t = t;

        switch (t)
        {
            case WSMsgType::BOOL:    f.value = r.U8() & 1; break;

            case WSMsgType::BYTE:    f.value = r.U8(); break;

            case WSMsgType::CHAR:    f.value = r.U8(); break;

            case WSMsgType::WORD:    f.value = r.U16(); break;

            case WSMsgType::SHORT:   f.value = r.U16(); break;

            case WSMsgType::DWORD:   f.value = r.U32(); break;

            case WSMsgType::INT:     f.value = r.U32(); break;

            case WSMsgType::DWORD64: f.value = r.U64(); break;

            case WSMsgType::INT64:   f.value = r.U64(); break;

            case WSMsgType::FLOAT:
                f.value = r.U32(); // raw IEEE 754 bits
                break;

            case WSMsgType::DOUBLE:
                f.value = r.U64(); // raw IEEE 754 bits
                break;

            case WSMsgType::RESREF:
            {
                const uint8_t slen = r.U8();
                f.data = r.Bytes(slen);
                break;
            }

            case WSMsgType::STRING:
            {
                const uint32_t slen = r.U32();
                f.data = r.Bytes(slen);
                break;
            }

            case WSMsgType::VOIDPTR:
            {
                const uint32_t slen = r.U32();
                f.data = r.Bytes(slen);
                break;
            }

            case WSMsgType::JSON:
            {
                const uint32_t slen = r.U32();
                f.data = r.Bytes(slen);
                break;
            }

            case WSMsgType::OBJECT_ID: f.value = r.U32(); break;

            case WSMsgType::LOCSTRING:
            {
                const uint8_t is_strref = r.U8();
                if (is_strref)
                {
                    const uint8_t gender = r.U8();
                    const uint32_t strref = r.U32();
                    f.value = static_cast<uint64_t>(strref) |
                        (static_cast<uint64_t>(gender) << 32) | (1ULL << 63);
                }
                else
                {
                    const uint32_t slen = r.U32();
                    f.data = r.Bytes(slen);
                    f.value = 0;
                }
                break;
            }

            default:
                LOG_WARNING("Unknown WSMsgType %d at frag %u during WS deserialization; aborting.",
                    static_cast<int>(t), i);
                return {};
        }

        result.push_back(std::move(f));
        ++i;
    }

    return result;
}
