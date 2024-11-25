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

// The only difference between IPv6Header and NetworkIPv6Header is that the
// byte order is ensured to be correct.
struct NetworkIPv6Address {
    NetworkOrdered<u64> word1;
    NetworkOrdered<u64> word2;

    explicit operator IPv6Address() const;
} __attribute__((packed));

class IPv6Address {
    static constexpr std::bitset<128> WORD1_MASK { 0xFFFFFFFFFFFFFFFF };
    static constexpr std::bitset<128> WORD2_MASK { std::bitset<128>(0xFFFFFFFFFFFFFFFF) << 64 };
    static constexpr std::bitset<128> BYTE_MASK { std::bitset<128>(0xFF) };

public:
    // Word 1 is bits 1-64, word 2 is bits 1-128
    IPv6Address(u64 word1, u64 word2)
    {
        m_address = word1;
        m_address |= std::bitset<128>(word2) << 64;
    }

    explicit operator NetworkIPv6Address()
    {
        return NetworkIPv6Address { (m_address & (WORD1_MASK)).to_ulong(), (m_address >> 64).to_ulong() };
    }

    std::string ToString() const;

private:
    std::bitset<128> m_address;
};

std::ostream& operator<<(std::ostream& os, const IPv6Address& ip6);
