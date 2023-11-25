//
// Created by Ryan Wolk on 5/23/22.
//

#pragma once

#include "IntDefs.h"
#include <array>
#include <string>

class EthernetMAC : public std::array<u8, 6> {
public:
    bool operator==(const EthernetMAC& other);
    bool operator!=(const EthernetMAC& other) { return !(*this == other); };
    std::string ToString() const;
    bool IsBroadcast() const;
} __attribute__((packed));
