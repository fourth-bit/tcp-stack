//
// Created by Ryan Wolk on 6/6/22.
//

#pragma once

class NetworkStack {
    enum class L2 {
        Ethernet,
    };
    enum class L3 {
        IPv4,
        IPv6,
        ARP,
    };
    enum class L4 {
        TCP,
        UDP,
    };
};
