//
// Created by Ryan Wolk on 3/27/22.
//

#pragma once

#include "IntDefs.h"
#include "NetworkOrder.h"
#include <optional>
#include <string>

class SubnetMask;
struct IPv4Hasher;

class __attribute__((packed)) IPv4Address {
    friend class SubnetMask;
    friend struct IPv4Hasher;

public:
    IPv4Address() = default;
    IPv4Address(const IPv4Address& other) = default;

    static std::optional<IPv4Address> FromString(const std::string&);
    explicit IPv4Address(NetworkOrdered<u32> addr)
        : m_address(addr)
    {
    }

    bool operator==(IPv4Address other) const
    {
        return m_address == other.m_address;
    }

    IPv4Address ApplySubnetMask(SubnetMask) const;
    NetworkOrdered<u32> GetAddress() const { return m_address; }
    std::string ToString() const;

    void SetFirstOctet(u8);
    void SetSecondOctet(u8);
    void SetThirdOctet(u8);
    void SetFourthOctet(u8);

private:
    NetworkOrdered<u32> m_address;
};

struct IPv4Hasher {
    size_t operator()(const IPv4Address& address) const
    {
        return std::hash<u32>()(address.m_address);
    }
};

class SubnetMask {
    friend class IPv4Address;

public:
    SubnetMask() = default;
    explicit SubnetMask(int bits)
        : m_bits(bits)
    {
    }

    IPv4Address GetMaskAsIP();

private:
    int m_bits;
};

struct ParseIPReturn {
    IPv4Address addr;
    SubnetMask subnet;
};

std::optional<ParseIPReturn> ParseIP(const std::string&);

std::ostream& operator<<(std::ostream&, const IPv4Address&);