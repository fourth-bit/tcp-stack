//
// Created by Ryan Wolk on 11/25/24.
//

#include <iomanip>

#include "IPv6Address.h"

NetworkIPv6Address::operator IPv6Address() const
{
    return { word1, word2 };
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
IPv6Address IPv6Address::ApplySubnetMask(SubnetMask6 mask) const
{
    return IPv6Address(m_address & mask.m_address);
}
bool IPv6Address::MatchesMulticast(IPv6Address multicast) const
{
    // 1. Check that the other one is actually a multicast
    const SubnetMask6 multicast_subnet (IPv6Address(std::bitset<128>(0xFFFF'FFFF'FFFF'FFFF) << 64 | std::bitset<128>(~(u64)0xFF'FFFF)));
    const IPv6Address multicast_base (0xff02'0000'0000'0000, 0x1'FF00'0000);

    if (multicast.ApplySubnetMask(multicast_subnet) == multicast_base) {
        // Get the least significant digits
        return ApplySubnetMask(~multicast_subnet) == multicast.ApplySubnetMask(~multicast_subnet);
    }

    return false;
}
bool IPv6Address::IsMulticast() const
{
    const SubnetMask6 multicast_subnet (IPv6Address(std::bitset<128>(0xFFFF'FFFF'FFFF'FFFF) << 64 | std::bitset<128>(~(u64)0xFF'FFFF)));
    const IPv6Address multicast_base (0xff02'0000'0000'0000, 0x1'FF00'0000);

    return ApplySubnetMask(multicast_subnet) == multicast_base;
}