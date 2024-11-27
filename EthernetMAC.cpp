//
// Created by Ryan Wolk on 5/23/22.
//

#include "EthernetMAC.h"
#include <cstdio>

bool EthernetMAC::operator==(const EthernetMAC& other)
{
    return this->at(0) == other[0]
        && this->at(1) == other[1]
        && this->at(2) == other[2]
        && this->at(3) == other[3]
        && this->at(4) == other[4]
        && this->at(5) == other[5];
}
bool EthernetMAC::IsBroadcast() const
{
    return this->at(0) == 0xff
        && this->at(1) == 0xff
        && this->at(2) == 0xff
        && this->at(3) == 0xff
        && this->at(4) == 0xff
        && this->at(5) == 0xff;
}
std::string EthernetMAC::ToString() const
{
    char buf[18];

    snprintf(buf, 18, "%02X:%02X:%02X:%02X:%02X:%02X",
        this->at(0),
        this->at(1),
        this->at(2),
        this->at(3),
        this->at(4),
        this->at(5));

    return std::string(buf);
}
bool EthernetMAC::IsIPv6Multicast(IPv6Address address) const
{
    if (this->at(0) == 0x33 && this->at(1) == 0x33 && this->at(2) == 0x0ff) {
        u32 last32bits = (address.Get() & std::bitset<128>(0xFF'FFFF)).to_ulong();

        return this->at(3) == (last32bits & 0xFF << 16)
            && this->at(4) == (last32bits & 0xFF << 8)
            && this->at(5) == (last32bits & 0xFF << 0);
    }

    return false;
}
