//
// Created by Ryan Wolk on 6/7/23.
//

#include <cassert>
#include <iomanip>
#include <iostream>

#include "NetworkBuffer.h"
#include "NetworkDevice.h"
#include "TCPManager.h"

void TCPManager::HandleIncoming(NetworkBuffer buffer, IPv4Connection ip_connection)
{
    using enum TCPHeader::Flags;

    auto& tcp = buffer.AddLayer<LayerType::TCP>(sizeof(TCPHeader));
    auto header = tcp.GetHeader();
    buffer.ResizeTop(header.header_length * 4);

    if (tcp.RunChecksum() != 0) {
#ifdef DEBUG_TCP
        std::cout << "Bad checksum in TCP Packet. Dropping." << std::endl;
#endif
        return;
    }

    TCPConnection connection {
        NetworkAddress(ip_connection.connected_ip),
        header.source_port,
        header.dest_port,
    };

#ifdef DEBUG_TCP
    DumpPacket(buffer, connection);
#endif

    auto it = m_open_connections.find(connection);
    if (it == m_open_connections.end()) {
        if (!m_listening_ports.contains(header.dest_port)) {
            // Trying to access a port that is not listening
            return;
        }

        auto* socket = m_listening_ports[header.dest_port];
        // MAYBE TODO: Refactor the State::Listen to another method, because the connection
        //             arg is only needed there.
        socket->HandleIncomingPacket(std::move(buffer), connection);
        return;
    }

    it->second->HandleIncomingPacket(std::move(buffer), connection);
}

void TCPManager::DumpPacket(NetworkBuffer& buffer, const TCPConnection& connection)
{
    std::cout << "TCP Packet From " << connection.connected_addr << ':' << connection.connected_port;
    std::cout << " to port " << connection.local_port << '\n';

    auto* tcp = buffer.GetLayer<LayerType::TCP>();
    if (tcp == nullptr) {
        std::cout << "Unable to Dump Header" << std::endl;
        return;
    }

    size_t packet_size = tcp->Size() + buffer.GetPayload().Size();
    u8* data = tcp->Data();
    std::cout << std::hex;
    for (size_t i = 0; i < packet_size; i++) {
        if (i % 8 == 0 && i != 0) {
            std::cout << "\n";
        }

        std::cout << std::setw(2) << (int)data[i] << " ";
    }
    std::cout << std::dec << std::endl;
}

bool TCPManager::ReservePort(TCPSocket* socket, u16 port)
{
    if (m_ports_in_use.contains(port)) {
        return false;
    }

    m_ports_in_use[port] = socket;
    return true;
}
bool TCPManager::RegisterListening(TCPSocket* socket)
{
    u16 port = socket->GetPort();

    if (port != 0 && m_ports_in_use.contains(port) && !m_registered_sockets.contains(socket)) {
        if (m_ports_in_use[port] == socket) {
            m_listening_ports[port] = socket;
            m_registered_sockets.insert(socket);
            return true;
        }
    }

    return false;
}
bool TCPManager::Unregister(TCPSocket* socket)
{
    if (m_registered_sockets.contains(socket)) {
        m_registered_sockets.erase(socket);
    }

    for (auto it = m_ports_in_use.begin(); it != m_ports_in_use.end(); ++it) {
        if (it->second == socket) {
            m_ports_in_use.erase(it);
        }
    }

    for (auto it = m_open_connections.begin(); it != m_open_connections.end(); ++it) {
        if (it->second == socket) {
            m_open_connections.erase(it);
            return true;
        }
    }

    for (auto it = m_listening_ports.begin(); it != m_listening_ports.end(); ++it) {
        if (it->second == socket) {
            m_listening_ports.erase(it);
            return true;
        }
    }

    return false;
}
std::optional<u16> TCPManager::ReserveEphemeral(TCPSocket* socket)
{
    int i = 0;

    while (i < ephemeral_ceil - ephemeral_floor) {
        if (m_ports_in_use.contains(current_ephemeral)) {
            current_ephemeral++;
            if (current_ephemeral > ephemeral_ceil) {
                current_ephemeral = ephemeral_floor;
            }
        } else {
            return current_ephemeral;
        }

        i++;
    }

    return { };
}

bool TCPManager::AlertOpenConnection(TCPSocket* listening_socket, TCPSocket* new_socket, TCPConnection connection)
{
    u16 port = listening_socket->GetPort();
    if (m_listening_ports.contains(port) && m_listening_ports[port] == listening_socket
        && !m_registered_sockets.contains(new_socket))
    {
        m_registered_sockets.insert(new_socket);
        m_open_connections[connection] = new_socket;
        return true;
    }

    return false;
}
bool TCPManager::RegisterConnection(TCPSocket* socket, TCPConnection connection)
{
    if (m_registered_sockets.contains(socket)) {
        return false;
    }

    m_open_connections[connection] = socket;
    m_registered_sockets.insert(socket);

    return true;
}
void TCPManager::SendPacket(NetworkBuffer buffer, NetworkAddress address)
{
    TCPLayer* layer = buffer.GetLayer<LayerType::TCP>();
    if (!layer) {
        std::cerr << "Unable to get TCPLayer from NetworkBuffer in TCPManager::SendPacket" << std::endl;
        return;
    }

    if (std::holds_alternative<IPv4Address>(address)) {
        auto ipv4_address = std::get<IPv4Address>(address);

        IPv4Layer::PsuedoHeader pheader {
            .source = the_net_dev->GetIPAddress(),
            .dest = ipv4_address,
            .zero = 0,
            .protocol = IPPROTO_TCP,
            .length = layer->GetHeaderSize() + buffer.GetPayload().Size()
        };

        layer->ApplyChecksum(pheader);

        m_net_dev->SendIPv4(std::move(buffer), ipv4_address, IPv4Header::TCP);
    }
}
