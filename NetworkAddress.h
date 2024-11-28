//
// Created by Ryan Wolk on 6/4/23.
//

#pragma once

#include <variant>

#include "IPv4Address.h"
#include "IntDefs.h"

// Fixme: Use 'using' instead
class NetworkAddress : public std::variant<IPv4Address , IPv6Address> { };

inline std::ostream& operator<<(std::ostream& stream, const NetworkAddress& address)
{
    if (std::holds_alternative<IPv4Address>(address)) {
        stream << std::get<IPv4Address>(address);
    } else if (std::holds_alternative<IPv6Address>(address)) {
        stream << std::get<IPv6Address>(address);
    } else {
        stream << "Not Implemented for NetworkAddress";
    }
    return stream;
}

struct NetworkAddressHasher {
    size_t operator()(const NetworkAddress& addr) const
    {
        if (std::holds_alternative<IPv4Address>(addr)) {
            return ipv4Hasher(std::get<IPv4Address>(addr));
        } else if (std::holds_alternative<IPv6Address>(addr)) {
            return ipv6Hasher(std::get<IPv6Address>(addr));
        }

        return 0;
    }

    IPv4Hasher ipv4Hasher {};
    IPv6Hasher ipv6Hasher {};
};

struct NetworkConnection {
    NetworkAddress source;
    NetworkAddress dest;
};