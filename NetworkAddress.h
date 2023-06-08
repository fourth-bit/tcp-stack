//
// Created by Ryan Wolk on 6/4/23.
//

#pragma once

#include <variant>

#include "IntDefs.h"
#include "IPv4Address.h"

// Fixme: Use 'using' instead
class NetworkAddress : public std::variant<IPv4Address/*, IPv6Address*/> {};

struct NetworkAddressHasher {
    size_t operator()(const NetworkAddress& addr) const {
        if (std::holds_alternative<IPv4Address>(addr)) {
            return ipv4Hasher(std::get<IPv4Address>(addr));
        }

        return 0;
    }

    IPv4Hasher ipv4Hasher {};
};