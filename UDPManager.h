//
// Created by Ryan Wolk on 4/30/22.
//

#pragma once

#include <unordered_map>

#include "IntDefs.h"
#include "NetworkBuffer.h"
#include "NetworkOrder.h"
#include "Protocols.h"
#include "Socket.h"

class NetworkDevice;
struct IPv4Connection;

class UDPBuffer : public IPv4Buffer {
public:
    static constexpr int HEADER_SIZE = sizeof(EthernetHeader) + sizeof(IPv4Header) + sizeof(UDPHeader);

    static UDPBuffer WithSize(size_t);

    static UDPBuffer FromVLBuffer(VLBuffer&&);
    explicit UDPBuffer(VLBuffer&& buf)
        : IPv4Buffer(std::move(buf))
    {
    }

    UDPHeader& GetUDPHeader();
    VLBufferView GetPayload();

    u16 RunUDPHeaderChecksum();
    void ApplyUDPHeaderChecksum();
};

class UDPManager {
    static const u16 ephemeral_floor = 0xC000;
    static const u16 ephemeral_ceil = 0xFFFF;
    static_assert(ephemeral_floor < ephemeral_ceil);

public:
    explicit UDPManager(NetworkDevice* dev)
        : m_net_dev(dev)
    {
    }

    bool RegisterPort(UDPSocket*, u16 port);
    bool Unregister(UDPSocket*);

    void HandleIncoming(NetworkBuffer, NetworkConnection);
    void SendDatagram(NetworkBuffer, NetworkAddress);

    const NetworkDevice* Device() const { return m_net_dev; }

    u16 NextEphemeralPort();

private:
    std::unordered_map<u16, UDPSocket*> m_ip4_port_socket_map {};
    u16 current_ephemeral { ephemeral_floor };
    NetworkDevice* m_net_dev;
};
