//
// Created by Ryan Wolk on 11/25/24.
//

#pragma once

#include <future>

#include "NetworkBuffer.h"

struct IPv6Connection;
class NetworkDevice;

class ICMPv6Manager {
    friend class NetworkDevice;

public:
    explicit ICMPv6Manager(NetworkDevice* dev);
    void HandleIncoming(NetworkBuffer, IPv6Connection);

    std::optional<EthernetMAC> SendNDP(IPv6Address);

private:
    std::unordered_map<IPv6Address, EthernetMAC, IPv6Hasher> m_ndp_map;
    std::unordered_map<IPv6Address, std::promise<void>, IPv6Hasher> m_ndp_wait_map;

    NetworkDevice* m_net_dev;
    NetworkBufferConfig m_config;
};
