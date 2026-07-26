#include <cstdint>
#include <cstring>
#include <deque>
#include <stdexcept>
#include <string>
#include <vector>

class lws;

//
// Constants
//

// Bump when the GN format or any BN/PM message format changes incompatibly.
#define NWNX_WSNETLAYER_PROTOCOL_VERSION 1u

#define FALSE                            0
#define TRUE                             1

// Abuse-prevention limits.
#define MAX_UNAUTHED_CONN_PER_IP         3u
#define LOGIN_TIMEOUT_SECS               30

//
// Helpers.cpp
//

bool IsPrivateIPv4(const char* ipv4);
bool IsValidIPv4(const char* ipv4);
bool TryGetForwardedForIPv4(lws* wsi, std::string& outIPv4);
std::string SanitizeString(const std::string& raw);

//
// ConnPool.cpp
// *Not protected under a mutex; caller must lock with g_mtx.*
//

#define NWN_MAX_PLAYERS    0xff
#define WS_CONN_START_ID   0x00010000u
#define MAX_WS_CONN_IDS    (NWN_MAX_PLAYERS + 6u)
#define INVALID_WS_CONN_ID 0u
bool IsValidWsConnId(uint32_t connId);
lws* GetWsiForWsConnId(uint32_t connId);
void SetWsiForWsConnId(uint32_t connId, lws* wsi);
void ClearWsiForWsConnId(uint32_t connId);
void ResetWsConnIdPool();
uint32_t AcquireWsConnId();
void ReleaseWsConnId(uint32_t connId);

//
// Message*.cpp
//

// Extended message type enum; values 1-16 are identical to CNWMessage::MessageType
// and can be safely cast. OBJECT_ID and LOCSTRING are WSNetLayer plugin-specific extensions.
enum class WSMsgType : uint8_t
{
    BITS = 1,
    BOOL = 2,
    BYTE = 3,
    CHAR = 4,
    WORD = 5,
    SHORT = 6,
    DWORD = 7,
    INT = 8,
    DWORD64 = 9,
    INT64 = 10,
    FLOAT = 11,
    DOUBLE = 12,
    RESREF = 13,
    STRING = 14,
    VOIDPTR = 15,
    JSON = 16,
    OBJECT_ID = 17, // uint32, distinct type tag from DWORD
    LOCSTRING = 18, // bool(is_strref) + [uint8 gender + uint32 strref] | [uint32 len + bytes]
};

struct MessageFrag
{
    WSMsgType t;
    uint64_t value = 0;    // integral/float/double bit-casted; LOCSTRING strref (see below)
    std::string data = ""; // RESREF, STRING, VOIDPTR, JSON; LOCSTRING string text

    // LOCSTRING layout:
    //   value == 0: data = string text
    //   value  > 0: value = strref | ((uint64_t)gender << 32) | (1ULL << 63)
};

class FragReadOverrun : public std::runtime_error
{
public:
    FragReadOverrun() : std::runtime_error("Attempted to read past end of message data") {}
};

using MessageFragBuffer = std::deque<MessageFrag>;
MessageFragBuffer& GetCurrentWriteBuffer();
uint8_t* GetLastWritePtr();
uint32_t GetLastWriteSize();

std::vector<uint8_t> SerializeFragBufferToWire(MessageFragBuffer& buf);
// raises FragReadOverrun:
MessageFragBuffer DeserializeWireToFragBuffer(const uint8_t* data, size_t len);

//
// Various
//

// Bit-exact reinterpret cast (C++17-compatible alternative to std::bit_cast).
template <typename To, typename From>
To bitcast(From from)
{
    static_assert(sizeof(To) == sizeof(From), "bitcast: size mismatch");
    To result;
    std::memcpy(&result, &from, sizeof(From));
    return result;
}
