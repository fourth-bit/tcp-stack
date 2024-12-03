//
// Created by Ryan Wolk on 4/30/22.
//

#include <cassert>
#include <iostream>

#include "NetworkDevice.h"
#include "UDPManager.h"

UDPBuffer UDPBuffer::WithSize(size_t size)
{
    return UDPBuffer(VLBuffer::WithSize(sizeof(EthernetHeader) + sizeof(IPv4Header) + sizeof(UDPHeader) + size));
}
UDPBuffer UDPBuffer::FromVLBuffer(VLBuffer&& buf)
{
    return UDPBuffer(std::move(buf));
}
UDPHeader& UDPBuffer::GetUDPHeader()
{
    return IPv4Buffer::GetPayload().as<UDPHeader>();
}
VLBufferView UDPBuffer::GetPayload()
{
    return IPv4Buffer::GetPayload().SubBuffer(sizeof(UDPHeader));
}
u16 UDPBuffer::RunUDPHeaderChecksum()
{
    assert(false);
}
void UDPBuffer::ApplyUDPHeaderChecksum()
{
    assert(false);
}

void UDPManager::HandleIncoming(NetworkBuffer buffer, NetworkConnection connection)
{
    auto& udp = buffer.AddLayer<LayerType::UDP>(sizeof(UDPHeader));
    if (udp.RunChecksum() != 0) {
        std::cout << "Bad Checksum in UDP Packet" << std::endl;
        return;
    }

    auto& header = udp.GetHeader();

    auto socket_it = m_ip4_port_socket_map.find(header.dest_port);

    if (socket_it != m_ip4_port_socket_map.end()) {
        UDPSocket* socket = socket_it->second;
//        if (!socket->ConnectionMatches({ connection.source }, header.source_port)) {
//            return;
//        }

        socket->AppendReadPayload(buffer.GetPayload(), { connection.source }, header.source_port);
    }
}
u16 UDPManager::NextEphemeralPort()
{
    if (current_ephemeral == ephemeral_ceil) {
        assert(false);
    }

    return current_ephemeral++;
}
bool UDPManager::RegisterPort(UDPSocket* socket, u16 port)
{
    if (m_ip4_port_socket_map.contains(port)) {
        return false;
    }

    m_ip4_port_socket_map[port] = socket;

    return true;
}
bool UDPManager::Unregister(UDPSocket* socket)
{
    for (auto it = m_ip4_port_socket_map.begin(); it != m_ip4_port_socket_map.end(); ++it) {
        if (it->second == socket) {
            m_ip4_port_socket_map.erase(it);
            return true;
        }
    }

    return false;
}
void UDPManager::SendDatagram(NetworkBuffer buf, NetworkAddress address)
{
    // Eventually differentiating sockaddrs for IPv4 and IPv6 will happen here
    UDPLayer* layer = buf.GetLayer<LayerType::UDP>();
    if (!layer) {
        std::cerr << "Malformed buffer (no UDPLayer) passed to UDPManager::SendDatagram" << std::endl;
        return;
    }

    if (std::holds_alternative<IPv4Address>(address)) {
        auto ipv4_address = std::get<IPv4Address>(address);

        IPv4Layer::PsuedoHeader pheader {
            .source = the_net_dev->GetIPAddress(),
            .dest = ipv4_address,
            .zero = 0,
            .protocol = IPPROTO_UDP,
            .length = sizeof(UDPHeader) + buf.GetPayload().Size(),
        };
        layer->ApplyChecksum(pheader);

        m_net_dev->SendIPv4(std::move(buf), ipv4_address, IPv4Header::UDP);
    } else if (std::holds_alternative<IPv6Address>(address)) {
        auto ipv6_address = std::get<IPv6Address>(address);

        IPv6Layer::PsuedoHeader pheader {
            .source = (NetworkIPv6Address)the_net_dev->GetIPv6Address(),
            .dest = (NetworkIPv6Address)ipv6_address,
            .length = sizeof(UDPHeader) + buf.GetPayload().Size(),
            .zero1 = 0,
            .zero2 = 0,
            .next_header = IPPROTO_UDP,
        };
        layer->ApplyChecksum(pheader);

        m_net_dev->SendIPv6(std::move(buf), ipv6_address, IPv6Header::UDP);
    }
}
