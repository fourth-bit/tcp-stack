//
// Created by Ryan Wolk on 11/25/24.
//

#include <iomanip>

#include "IPv6Address.h"

NetworkIPv6Address::operator IPv6Address() const
{
    return { word2, word1 };
}

std::ostream& operator<<(std::ostream& os, const IPv6Address& ip6)
{
    return os << ip6.ToString();
}

std::string IPv6Address::ToString() const
{
    std::stringstream ss;
    ss << std::hex;
    for (int i = 7; i >= 0; i--) {
        std::bitset<128> two_bytes = m_address >> (i * 16) & (BYTE_MASK | (BYTE_MASK << 8));
        unsigned long raw_short = two_bytes.to_ulong();
        ss << std::setw(4) << std::setfill('0') << raw_short;
        if (i != 0) {
            ss << ":";
        }
    }

    return ss.str();
}
