//
// Created by Ryan Wolk on 3/27/22.
//

#pragma once

#include <chrono>
#include <condition_variable>
#include <future>
#include <optional>
#include <unordered_map>

#include "IPv4Address.h"
#include "NetworkBuffer.h"

class NetworkDevice;
struct IPv4Connection;

class ICMPManager {
public:
    explicit ICMPManager(NetworkDevice* dev);

    void HandleIncoming(NetworkBuffer, IPv4Connection);
    // Blocking function to send ICMP Echo or ping
    std::optional<std::chrono::microseconds> SendEchoRequest(IPv4Address);

private:
    std::unordered_map<int, std::promise<void>> m_connection_map {};
    NetworkBufferConfig m_config;
    NetworkDevice* m_net_dev;
};
