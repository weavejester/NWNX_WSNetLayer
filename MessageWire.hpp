#pragma once

#include <cstdint>
#include <stdexcept>
#include <vector>

class ProtocolError : public std::runtime_error
{
public:
    ProtocolError(const std::string& what) : std::runtime_error(what) {}
};

class ReadOverrun : public ProtocolError
{
public:
    ReadOverrun() : ProtocolError("Attempted to read past end of message data") {}
};

struct WireReader
{
    const std::vector<uint8_t> data;
    size_t pos = 0;

    WireReader(const uint8_t* d, size_t l) : data(std::vector<uint8_t>(d, d + l)), pos(0) {}
    WireReader(const std::vector<uint8_t>& data) : data(data) {}

    size_t len() const { return data.size(); }
    bool at_end() const { return pos >= len(); }

    uint8_t U8()
    {
        if (pos + 1 > len())
        {
            throw ReadOverrun();
        }
        return data[pos++];
    }
    uint16_t U16()
    {
        if (pos + 2 > len())
        {
            throw ReadOverrun();
        }
        uint16_t v = static_cast<uint16_t>(data[pos]) | (static_cast<uint16_t>(data[pos + 1]) << 8);
        pos += 2;
        return v;
    }
    uint32_t U32()
    {
        if (pos + 4 > len())
        {
            throw ReadOverrun();
        }
        uint32_t v = uint32_t(data[pos]) | (uint32_t(data[pos + 1]) << 8) |
            (uint32_t(data[pos + 2]) << 16) | (uint32_t(data[pos + 3]) << 24);
        pos += 4;
        return v;
    }
    uint64_t U64()
    {
        if (pos + 8 > len())
        {
            throw ReadOverrun();
        }
        uint64_t v = 0;
        for (int i = 0; i < 8; ++i)
            v |= static_cast<uint64_t>(data[pos + i]) << (8 * i);
        pos += 8;
        return v;
    }
    std::string Bytes(size_t n)
    {
        if (pos + n > len())
        {
            throw ReadOverrun();
        }
        std::string s(reinterpret_cast<const char*>(data.data() + pos), n);
        pos += n;
        return s;
    }
};

struct WireWriter
{
    std::vector<uint8_t> data;
    WireWriter() = default;
    WireWriter(const WireWriter&) = delete;
    WireWriter& operator=(const WireWriter&) = delete;

    void WriteU8(uint8_t x) { data.push_back(x); }
    void WriteU16(uint16_t x)
    {
        data.push_back(static_cast<uint8_t>(x & 0xFF));
        data.push_back(static_cast<uint8_t>((x >> 8) & 0xFF));
    }
    void WriteU32(uint32_t x)
    {
        data.push_back(static_cast<uint8_t>(x & 0xFF));
        data.push_back(static_cast<uint8_t>((x >> 8) & 0xFF));
        data.push_back(static_cast<uint8_t>((x >> 16) & 0xFF));
        data.push_back(static_cast<uint8_t>((x >> 24) & 0xFF));
    }
    void WriteU64(uint64_t x)
    {
        for (int i = 0; i < 8; ++i)
            data.push_back(static_cast<uint8_t>((x >> (8 * i)) & 0xFF));
    }
    void WriteBytes(const char* payload, size_t len)
    { data.insert(data.end(), payload, payload + len); }
};
