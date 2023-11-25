//
// Created by Ryan Wolk on 3/27/22.
//

#include "IPv4Address.h"
#include <optional>
#include <sstream>

std::optional<IPv4Address> IPv4Address::FromString(const std::string& str)
{
    std::stringstream ss;
    ss << str;

    u32 ip = 0;

    for (int i = 0; i < 4; i++) {
        ip <<= 8;
        u32 next_octet = 0;

        ss >> next_octet;

        if (next_octet > 255) {
            return {};
        }

        ip += next_octet;

        if (ss.get() != '.' && i != 3) {
            return {};
        }
    }

    return IPv4Address(NetworkOrdered(ip));
}

IPv4Address SubnetMask::GetMaskAsIP()
{
    u32 ip;
    for (int i = 0; i < m_bits; i++) {
        ip <<= 1;
        ip += 1;
    }

    ip <<= 32 - m_bits;

    return IPv4Address(ip);
}

IPv4Address IPv4Address::ApplySubnetMask(SubnetMask mask) const
{
    u32 ip_mask = mask.GetMaskAsIP().m_address;
    u32 this_addr = m_address;

    u32 result_addr = this_addr & ip_mask;

    return IPv4Address(result_addr);
}
void IPv4Address::SetFirstOctet(u8 val)
{
    u32 this_addr = m_address;
    this_addr &= ~0xFF;
    this_addr += val;

    m_address = this_addr;
}
void IPv4Address::SetSecondOctet(u8 val)
{
    u32 this_addr = m_address;
    this_addr &= ~(0xFF << 8);
    this_addr += val << 8;

    m_address = this_addr;
}
void IPv4Address::SetThirdOctet(u8 val)
{
    u32 this_addr = m_address;
    this_addr &= ~(0xFF << 16);
    this_addr += val << 16;

    m_address = this_addr;
}
void IPv4Address::SetFourthOctet(u8 val)
{
    u32 this_addr = m_address;
    this_addr &= ~(0xFF << 24);
    this_addr += val << 24;

    m_address = this_addr;
}

std::string IPv4Address::ToString() const
{
    std::stringstream ss;
    u32 h_address = m_address;
    ss << (h_address >> 24) << '.'
       << (h_address & 0x0F00 >> 16) << '.'
       << (h_address & 0x00F0 >> 8) << '.'
       << (h_address & 0x000F);

    return ss.str();
}

std::optional<ParseIPReturn> ParseIP(const std::string& str)
{
    auto maybe_ip = IPv4Address::FromString(str);
    if (!maybe_ip) {
        return {};
    }

    auto ip = *maybe_ip;

    int subnet_bits = 0;
    auto it = std::find(str.begin(), str.end(), '/');
    if (it != str.end()) {
        ++it;

        std::stringstream ss;
        for (; it != str.end(); ++it)
            ss << *it;

        ss >> subnet_bits;
    }

    return ParseIPReturn { ip, SubnetMask(subnet_bits) };
}

std::ostream& operator<<(std::ostream& os, const IPv4Address& ip)
{
    return os << ip.ToString();
}
