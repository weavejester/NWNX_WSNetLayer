#include <arpa/inet.h>
#include <cstdlib>
#include <cstring>
#include <libwebsockets.h>
#include <string>

bool IsPrivateIPv4(const char* ipv4)
{
    if (!ipv4)
        return false;

    return (std::strcmp(ipv4, "127.0.0.1") == 0) || (std::strncmp(ipv4, "10.", 3) == 0) ||
        (std::strncmp(ipv4, "192.168.", 8) == 0) ||
        (std::strncmp(ipv4, "172.", 4) == 0 && std::atoi(ipv4 + 4) >= 16 &&
            std::atoi(ipv4 + 4) <= 31);
}

bool IsValidIPv4(const char* ipv4)
{
    in_addr addr {};
    return ipv4 != nullptr && inet_pton(AF_INET, ipv4, &addr) == 1;
}

bool TryGetForwardedForIPv4(lws* wsi, std::string& outIPv4)
{
    char xff[256] = {};
    const int copied = lws_hdr_copy(wsi, xff, sizeof(xff), WSI_TOKEN_X_FORWARDED_FOR);
    if (copied <= 0)
        return false;

    std::string candidate(xff);

    // X-Forwarded-For can be a chain (client, proxy1, proxy2).  We trust only the first hop.
    const size_t comma = candidate.find(',');
    if (comma != std::string::npos)
        candidate.resize(comma);

    const auto isSpace = [](unsigned char c) { return std::isspace(c) != 0; };
    while (!candidate.empty() && isSpace(static_cast<unsigned char>(candidate.front())))
        candidate.erase(candidate.begin());
    while (!candidate.empty() && isSpace(static_cast<unsigned char>(candidate.back())))
        candidate.pop_back();

    if (!IsValidIPv4(candidate.c_str()))
        return false;

    outIPv4 = std::move(candidate);
    return true;
}

std::string SanitizeString(const std::string& raw)
{
    std::string safe;
    safe.reserve(raw.size() * 2); // Reserve extra space to avoid reallocations

    for (unsigned char c : raw)
    {
        // Allow printable ASCII characters and high-bit UTF-8 characters.
        // Filter out ASCII control characters (0x00-0x1F) and DEL (0x7F).
        if (c >= 32 && c != 127)
        {
            safe += c;
        }
        else
        {
            // Escape binary/control characters as \xNN
            char hex[5];
            snprintf(hex, sizeof(hex), "\\x%02X", c);
            safe += hex;
        }
    }
    return safe;
}
