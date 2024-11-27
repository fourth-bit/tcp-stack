//
// Created by Ryan Wolk on 11/24/24.
//

#pragma once

#include <bitset>
#include <sstream>
#include <string>

#include "IntDefs.h"
#include "NetworkOrder.h"

struct NetworkIPv6Address;
class IPv6Address;
class SubnetMask6;

// The only difference between IPv6Header and NetworkIPv6Header is that the
// byte order is ensured to be correct.
struct NetworkIPv6Address {
    NetworkOrdered<u64> word1;
    NetworkOrdered<u64> word2;

    explicit operator IPv6Address() const;
} __attribute__((packed));

class IPv6Address {
    friend struct IPv6Hasher;

    static constexpr std::bitset<128> WORD2_MASK { 0xFFFFFFFFFFFFFFFF };
    static constexpr std::bitset<128> WORD1_MASK { std::bitset<128>(0xFFFFFFFFFFFFFFFF) << 64 };
    static constexpr std::bitset<128> BYTE_MASK { std::bitset<128>(0xFF) };

public:
    IPv6Address()
        : m_address(0)
    {
    }

    explicit IPv6Address(std::bitset<128> address)
        : m_address(address)
    {
    }

    // Word 1 is bits 1-64, word 2 is bits 1-128
    IPv6Address(u64 word2, u64 word1)
    {
        m_address = word1;
        m_address |= std::bitset<128>(word2) << 64;
    }

    explicit operator NetworkIPv6Address() const
    {
        return NetworkIPv6Address { (m_address >> 64).to_ulong(), (m_address & (WORD2_MASK)).to_ulong() };
    }

    std::string ToString() const;
    std::bitset<128> Get() const { return m_address; }

    bool operator==(IPv6Address other) const
    {
        return m_address == other.m_address;
    }

    bool MatchesMulticast(IPv6Address) const;
    bool IsMulticast() const;

    IPv6Address ApplySubnetMask(SubnetMask6) const;

protected:
    std::bitset<128> m_address;
};
struct IPv6Hasher {
    size_t operator()(const IPv6Address& address) const
    {
        return std::hash<std::bitset<128>>()(address.m_address);
    }
};
class SubnetMask6 : public IPv6Address {
    friend class IPv6Address;

public:
    SubnetMask6()
        : IPv6Address()
    {
    }

    explicit SubnetMask6(IPv6Address address)
        : IPv6Address(address)
    {
    }

    explicit SubnetMask6(std::bitset<128> address)
        : IPv6Address(address)
    {
    }

    IPv6Address toAddress() { return IPv6Address(m_address); }

    SubnetMask6 operator~() const { return SubnetMask6(~m_address); }
};

std::ostream& operator<<(std::ostream& os, const IPv6Address& ip6);
