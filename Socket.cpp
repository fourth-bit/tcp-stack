//
// Created by Ryan Wolk on 4/30/22.
//

#include <cassert>
#include <iostream>

#include "NetworkDevice.h"
#include "Socket.h"
#include "UDPManager.h"
#include "Badge.h"

struct Route {
    EthernetMAC targetMAC;
    IPv4Address next_hop;
};

u8 socktype_to_ipproto(SOCK_TYPE type)
{
    switch(type) {
    case SOCK_TYPE::STREAM:
        return IPPROTO_TCP;
    case SOCK_TYPE::DATAGRAM:
        return IPPROTO_UDP;
    case SOCK_TYPE::RAW:
        return IPPROTO_RAW;
    }
}

Socket* Socket::Create(PROTOCOL proto, SOCK_TYPE type)
{
    const NetworkBufferConfig* config { nullptr };
    if (proto == PROTOCOL::INTERNET) {
        config = &the_net_dev->GetIPv4Config();

        // Sanity Check
        if (!config->HasLayer<LayerType::IPv4>()) {
            std::cerr << "Fatal: Malformed IPv4 Buffer Config in the_net_dev" << std::endl;
            assert(false);
        }
    } else if (proto == PROTOCOL::INTERNET6) {
        std::cerr << "No Support for IPv6 Yet" << std::endl;
        assert(false);
        // config = the_net_dev->GetIPv6Config();
    }

    if (config == nullptr) {
        std::cerr << "Null NetworkBufferConfig in Socket::Create" << std::endl;
        return nullptr;
    }

    if (type == SOCK_TYPE::STREAM) {
        assert(false);
    } else if (type == SOCK_TYPE::DATAGRAM) {
        return new UDPSocket(&the_net_dev->GetUDPManager(), *config, {});
    } else if (type == SOCK_TYPE::RAW) {
        assert(false);
    }

    return nullptr;
}

static std::optional<Route> MakeRoutingDecision(IPv4Address to)
{
    assert(the_net_dev != nullptr);

    SubnetMask mask = the_net_dev->GetSubnetMask();
    IPv4Address target;
    if (to.ApplySubnetMask(mask) == the_net_dev->GetIPAddress().ApplySubnetMask(mask)) {
        target = to;
    } else {
        target = the_net_dev->GetGateway();
    }

    auto result = the_net_dev->SendArp(target);
    if (!result) {
        return {};
    }

    return { Route { *result, to, } };
}

UDPSocket::UDPSocket(UDPManager* manager, const NetworkBufferConfig& config, Badge<Socket>)
    : udpManager(manager)
    , m_general_config(config)
{
}
UDPSocket::UDPSocket(UDPManager* manager, const NetworkBufferConfig& config) // Private version
    : udpManager(manager)
    , m_general_config(config)
{
}
UDPSocket::~UDPSocket() noexcept
{
    if (is_open) {
        Close();
    }
}

std::optional<UDPSocket> UDPSocket::To()
{
    // TODO: Request PORT/Connection from the manager
    assert(false);
}

bool UDPSocket::Connect(NetworkAddress address, u16 port)
{
    if (std::get<2>(m_connected_to)) {
        return false;
    }

    m_connected_to = std::make_tuple(address, port, true);

    return true;
}
bool UDPSocket::Bind(u16 port)
{
    if (m_bound_port == 0) {
        if (!udpManager->RegisterPort(this, port)) {
            return false;
        }

        m_bound_port = port;
        // is_listening = true;

        m_udp_config.source_port = port;
        return true;
    }

    return false;
}

ErrorOr<VLBuffer> UDPSocket::Read()
{
    if (is_listening) {
        return SocketError::Make(SocketError::Code::ReadFromConnectionSocket);
    }

    std::unique_lock lock (read_lock);
    if (in_read) {
        // Disallow simultaneous reads
        return SocketError::Make(SocketError::Code::SimultaneousRead);
    }
    in_read = true;

    if (m_read_buffers.empty()) {
        lock.unlock();
        std::unique_lock cv_unlock(read_cv_lock);
        read_cv.wait(cv_unlock);
        lock.lock();
    }

    auto datagram = std::move(m_read_buffers.front());
    m_read_buffers.pop_front();
    in_read = false;
    return std::move(datagram.buffer);
}

ErrorOr<UDPSocket::DatagramInfo> UDPSocket::ReadFrom()
{
    std::unique_lock lock (read_lock);
    if (in_read) {
        // Disallow simultaneous reads
        return SocketError::Make(SocketError::Code::SimultaneousRead);
    }
    in_read = true;

    if (m_read_buffers.empty()) {
        lock.unlock();
        std::unique_lock cv_unlock(read_cv_lock);
        read_cv.wait(cv_unlock);
        lock.lock();
    }

    auto info = std::move(m_read_buffers.front());
    m_read_buffers.pop_front();
    in_read = false;
    return info;
}

u64 UDPSocket::Write(const VLBufferView view)
{
    if (is_listening) {
        // Todo: Issue an Error or a Warning
        return 0;
    }

    std::lock_guard write_unlock(write_lock);

    if (!std::get<2>(m_connected_to)) {
        return 0;
    }

    if (!has_written && m_bound_port == 0) {
        has_written = true;
        Bind(udpManager->NextEphemeralPort());
    }

    return WriteTo(view, std::get<0>(m_connected_to), std::get<1>(m_connected_to));
}

u64 UDPSocket::WriteTo(const VLBufferView view, NetworkAddress address, u16 port)
{
    if (is_listening) {
        // Todo: Issue an Error or a Warning
        return 0;
    }

    u64 write_amount = std::min(view.Size(), udpManager->Device()->GetMTU() - m_general_config.HeaderSize() - sizeof(UDPHeader));
    // NetworkBuffer buffer_to_write = m_config.BuildBuffer(write_amount);
    NetworkBuffer buffer_to_write = m_general_config.BuildBuffer(sizeof(UDPHeader) + write_amount);
    auto& udp = buffer_to_write.AddLayer<LayerType::UDP>(sizeof(UDPHeader));
    m_udp_config.ConfigureLayer(udp);

    u8* data = buffer_to_write.GetPayload().Data();
    std::copy(view.Data(), view.Data() + write_amount, data);

    UDPLayer* udpLayer = buffer_to_write.GetLayer<LayerType::UDP>();
    udpLayer->SetDestPort(port);
    udpLayer->SetLength(sizeof(UDPHeader) + write_amount);
    // Due to psuedo-headers being dependent on the IP Header, checksumming is done in UDPManager

    udpManager->SendDatagram(std::move(buffer_to_write), address);
    return write_amount;
}

bool UDPSocket::ConnectionMatches(NetworkAddress address, u16 port)
{
    return (std::get<2>(m_connected_to) && address == std::get<0>(m_connected_to) && port == std::get<1>(m_connected_to))
        || is_listening;
}
void UDPSocket::AppendReadPayload(VLBufferView view, NetworkAddress in_addr, u16 in_port)
{
    if (is_listening) {
        UDPSockInfo info { in_addr, in_port };
        auto target_socket = m_listening_subsockets.find(info);

        if (target_socket != m_listening_subsockets.end()) {
            target_socket->second->AppendReadPayload(view, in_addr, in_port);
        } else {
            m_accept_backlog.push_back({ view.CopyToVLBuffer(), in_addr, in_port });
            accept_cv.notify_one();
        }
    } else {
        std::lock_guard read_unlock(read_lock);

        m_read_buffers.push_back({ view.CopyToVLBuffer(), in_addr, in_port });
        read_cv.notify_one();
    }
}

bool UDPSocket::Close()
{
    is_open = false;

    if (parent != nullptr) {
        return parent->UnregisterSubsocket(this);
    }

    return udpManager->Unregister(this);
}

bool UDPSocket::Listen()
{
    // if (m_bound_port == 0)
    if (is_listening || parent != nullptr) {
        return false;
    }

    is_listening = true;
    return true;
}

ErrorOr<std::pair<Socket*, SocketInfo*>> UDPSocket::Accept()
{
    if (!is_listening) {
        return SocketError::Make(SocketError::Code::AcceptOnNonListeningSocket);
    }

    std::unique_lock lock (accept_lock);
    if (in_accept) {
        // Disallow Simultaneous Accepts
        return SocketError::Make(SocketError::Code::SimultaneousAccept);
    }
    in_accept = true;

    if (m_accept_backlog.empty()) {
        lock.unlock();
        std::unique_lock cv_unlock(accept_cv_lock);
        accept_cv.wait(cv_unlock);
        lock.lock();
    }

    auto& [buffer, in_addr, in_port] = m_accept_backlog.front();
    auto* socket = new UDPSocket(udpManager, m_general_config);
    socket->parent = this;
    socket->m_connected_to = { in_addr, in_port, true };
    socket->m_bound_port = m_bound_port;
    socket->m_udp_config = m_udp_config;

    m_listening_subsockets[UDPSockInfo{in_addr, in_port}] = socket;
    socket->AppendReadPayload(buffer.AsView(), in_addr, in_port);

    auto* info = new PortSocketInfo { in_addr, in_port };
    m_accept_backlog.pop_front();

    in_accept = false;

    return { { socket, info } };
}

bool UDPSocket::UnregisterSubsocket(UDPSocket* socket)
{
    UDPSockInfo sockinfo { std::get<0>(socket->m_connected_to), std::get<1>(socket->m_connected_to) };
    auto it = m_listening_subsockets.find(sockinfo);
    if (it != m_listening_subsockets.end()) {
        m_listening_subsockets.erase(it);
        return true;
    }

    return false;
}
