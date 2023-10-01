//
// Created by Ryan Wolk on 4/30/22.
//

#include <cassert>
#include <iostream>
#include <sstream>

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
        return new TCPSocket(&the_net_dev->GetTCPManager(), *config, {});
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

std::string SocketError::ToString()
{
    std::stringstream ss;

    switch (code) {
    case Code::SimultaneousRead:
        ss << "Attempt to Simultaneously Read to Socket";
        break;
    case Code::ReadFromConnectionSocket:
        ss << "Attempt to Read to a Socket Designated for Listening";
        break;
    case Code::ReadFromClosedSocket:
        ss << "Attempt to read from Closed Socket";
        break;
    case Code::WriteToConnectionSocket:
        ss << "Attempt to read to a Socket Designated for Listening";
        break;
    case Code::SimultaneousAccept:
        ss << "Attempt to Call Accept Simultaneously on Socket";
        break;
    case Code::AcceptOnNonListeningSocket:
        ss << "Attempt to Accept New Connections on a Socket Not in Listen State";
        break;
    }

    if (!information.empty()) {
        ss << ": " << information;
    }

    return ss.str();
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
    // Due to pseudo-headers being dependent on the IP Header, checksumming is done in UDPManager

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

TCPSocket::TCPSocket(TCPManager* manager, const NetworkBufferConfig& config, Badge<Socket>)
    : m_manager(manager)
    , m_general_config(config)
    , m_tcb { .state=State::CLOSED }
    , m_receive_buffer(65535)
{
}
TCPSocket::TCPSocket(TCPManager* manager, const NetworkBufferConfig& config)
    : m_manager(manager)
    , m_general_config(config)
    , m_tcb { .state=State::CLOSED }
    , m_receive_buffer(65535)
{
}

bool TCPSocket::Connect(NetworkAddress connected_address, u16 connected_port)
{
    // This call only makes sense in a not yet open socket
    if (getState() != State::CLOSED) {
        return false;
    }

    if (m_bound_port == 0) {
        auto port = m_manager->ReserveEphemeral(this);
        if (!port.has_value()) {
            return false;
        }

        m_bound_port = *port;
        m_tcp_config.source_port = m_bound_port;
    }

    bool registered = m_manager->RegisterConnection(this, TCPConnection{ connected_address, connected_port, m_bound_port });
    if (!registered) {
        return false;
    }

    // Initialize the TCB
    m_connected_addr = connected_address;
    m_connected_port = connected_port;
    m_tcp_config.dest_port = connected_port;
    m_tcb.state = State::SYN_SENT;
    m_tcb.SND.ISS = GenerateISS();
    m_tcb.SND.UNA = m_tcb.SND.ISS;
    m_tcb.SND.NXT = m_tcb.SND.ISS + 1;
    m_tcb.RCV.WND = m_receive_buffer.RemainingSpace();

    SendTCPPacket(TCPHeader::SYN, {}, m_tcb.SND.ISS.Get(), 0);

    return true;
}
bool TCPSocket::Bind(u16 port)
{
    if (m_bound_port != 0) {
        return false;
    }

    bool res = m_manager->ReservePort(this, port);
    if (res) {
        m_bound_port = port;
        m_tcp_config.source_port = m_bound_port;

        return true;
    }

    return false;
}
bool TCPSocket::Listen()
{
    bool res = m_manager->RegisterListening(this);

    if (!res) {
        return false;
    }

    m_tcb.state = State::LISTEN;

    return true;
}
ErrorOr<std::pair<Socket*, SocketInfo*>> TCPSocket::Accept()
{
    for (;;);
}
ErrorOr<VLBuffer> TCPSocket::Read()
{
    assert(false);
}
u64 TCPSocket::Write(const VLBufferView)
{
    assert(false);
    return 0;
}
bool TCPSocket::Close()
{
    assert(false);
    return 0;
}

void TCPSocket::HandleIncomingPacket(NetworkBuffer buffer, TCPConnection connection)
{
    // FIXME: RFC 5961 Recommendations

    using enum TCPHeader::Flags;

    auto* tcp_layer = buffer.GetLayer<LayerType::TCP>();
    if (tcp_layer == nullptr) {
        std::cerr << "Error: Invalid Buffer Passed to TCPSocket::HandleIncomingPacket" << std::endl;
        return;
    }

    auto& header = tcp_layer->GetHeader();
    size_t segment_length = buffer.GetPayload().Size();
    Modular<u32> seq_num = header.seq_num.Convert();
    Modular<u32> ack_num = header.ack_num.Convert();

    // RFC 9293 Section 3.10.7 Segment Arrives
    switch (m_tcb.state) {
    case State::CLOSED:
        /* All data in the incoming segment is discarded. An incoming segment containing a RST is
         * discarded. An incoming segment not containing a RST causes a RST to be sent in response.
         * The acknowledgment and sequence field values are selected to make the reset sequence
         * acceptable to the TCP endpoint that sent the offending segment. */
        if (header.flags & RST) {
            // Ignore if RST is set
            break;
        }

        if (header.flags & ACK) {
            // Set the syn_num for the packet supposedly acked
            SendTCPPacket(RST, {}, ack_num.Get());
        } else {
            // ACK whatever was sent, and reset
            SendTCPPacket(RST | ACK, {}, 0, header.seq_num + segment_length);
        }
        break;
    case State::LISTEN:
        // First, check for a RST
        if (header.flags & RST) {
            // Ignore
            break;
        }

        // Second, check for an ACK
        if (header.flags & ACK) {
            // This is bad, so send a reset
            SendTCPPacket(RST, {}, ack_num.Get());
        }

        // Third, check for a SYN
        if (header.flags & SYN) {
            // Todo: If the SYN bit is set, check the security. If the security/compartment on the incoming
            //       segment does not exactly match the security/compartment in the TCB, then send a reset
            //       and return.

            auto* new_socket = new TCPSocket(m_manager, m_general_config);

            m_manager->AlertOpenConnection(this, new_socket, connection);

            // Setup TCB according to spec
            new_socket->m_tcb.RCV.IRS = header.seq_num.Convert();
            new_socket->m_tcb.RCV.NXT = header.seq_num + 1;
            new_socket->m_tcb.RCV.WND = new_socket->m_receive_buffer.RemainingSpace();
            new_socket->m_tcb.SND.ISS = GenerateISS();
            new_socket->m_tcb.SND.NXT = new_socket->m_tcb.SND.ISS + 1;
            new_socket->m_tcb.SND.UNA = new_socket->m_tcb.SND.ISS;

            // Fixme: Fill in information about the connected party
            new_socket->m_bound_port = m_bound_port;
            new_socket->m_connected_addr = connection.connected_addr;
            new_socket->m_connected_port = connection.connected_port;

            new_socket->m_tcp_config.source_port = m_bound_port;
            new_socket->m_tcp_config.dest_port = connection.connected_port;

            new_socket->SendTCPPacket(SYN | ACK, {}, new_socket->m_tcb.SND.ISS.Get(), new_socket->m_tcb.RCV.NXT.Get());
            new_socket->m_tcb.state = State::SYN_RCVD;
        } else {
            // Should not be possible to get here, but in this case, drop the packet
            break;
        }

        break;
    case State::SYN_SENT:
        // First, check the ACK bit for a valid ack number
        if (header.flags & ACK) {
            // Check that it is in range of SND.ISS and SND.NXT, here SND.UNA and SND.ISS should be the same
            if (!ack_num.InRange(m_tcb.SND.ISS, m_tcb.SND.NXT, LowerOpen {})) {
                SendTCPPacket(RST, {}, ack_num.Get(), 0);

                // Then discard
                break;
            }
        }

        // Second, check the RST bit
        if (header.flags & RST) {
            // Fixme: Issue an error to the user that the connection failed
            m_tcb.state = State::CLOSED;
            // Todo: Alert manager that we are now closed
            break;
        }

        // Fixme: Third check the security
        //        If the security/compartment in the segment does not exactly match the security/
        //        compartment in the TCB, send a reset:

        // Fourth, check the SYN bit
        if (header.flags & SYN) {
            m_tcb.RCV.IRS = header.seq_num.Convert();
            m_tcb.RCV.NXT = header.seq_num + 1;

            if (header.flags & ACK) {
                m_tcb.SND.UNA = header.ack_num.Convert();
                // Fixme: Remove any packets that need retransmission from the retransmission queue

                // Already verified that the ack_num is greater than the ISS, so no need to check again
                m_tcb.state = State::ESTABLISHED;
                SendTCPPacket(ACK, {}, m_tcb.SND.NXT.Get(), m_tcb.RCV.NXT.Get());
            } else {
                // No ACK means possible simultaneous open, so go into SYN_RCVD
                m_tcb.state = State::SYN_RCVD;
                SendTCPPacket(SYN | ACK, {}, m_tcb.SND.ISS.Get(), m_tcb.RCV.NXT.Get());
            }

            m_tcb.SND.WND = header.window_size;
            m_tcb.SND.WL1 = header.seq_num.Convert();
            m_tcb.SND.WL2 = header.ack_num.Convert();

            // Todo: If there are other controls or text in the segment, queue them for processing after the
            //       ESTABLISHED state has been reached, return.
            //       Note that it is legal to send and receive application data on SYN segments (this is the "text
            //       in the segment" mentioned above). There has been significant misinformation and
            //       misunderstanding of this topic historically. Some firewalls and security devices consider
            //       this suspicious. However, the capability was used in T/TCP and is used in TCP Fast
            //       Open (TFO) , so is important for implementations and network devices to permit.
        }
        break;
    case State::SYN_RCVD: {
        // Validate the segment's sequence number
        bool valid = ValidateSequenceNumber(segment_length, seq_num);
        // Valid is false otherwise

        // If an incoming segment is not acceptable, an acknowledgement should be sent in
        // reply (unless the RST bit is set, if so drop the segment and return)

        if (!valid) {
            if (header.flags & RST) {
#ifdef DEBUG_TCP
                std::cerr << "Dropping packet due to RST and invalid seq_num for tcb" << std::endl;
#endif
                break;
            }

            // SendTCPPacket(ACK, {}, m_tcb.SND.NXT.Get(), m_tcb.RCV.NXT.Get());

            // After sending ACK drop the packet and return
#ifdef DEBUG_TCP
            std::cerr << "Dropping packet due to invalid seq_num for tcb" << std::endl;
#endif
            break;
        }

        // Second check the RST bit
        if (header.flags & RST) {
            // If this was initiated via passive OPEN (through LISTEN), close the connection quietly
            m_manager->Unregister(this);
            m_tcb.state = State::CLOSED;

            // TODO: Otherwise, close the connection and tell the user connection refused
            // TODO: Remove all segments from the retransmission queue

            break;
        }

        if (seq_num != m_tcb.RCV.NXT) {
            // Todo: Queue segment to be processed later
            // For now, we drop it
            break;
        }

        // TODO: Third Check security/precedence

        // Fourth, check the SYN bit

        if (header.flags & SYN) {
            // At this point if the SYN bit is sent, it is an error
            // Send a reset
            SendTCPPacket(RST, {});
            m_manager->Unregister(this);
            m_tcb.state = State::CLOSED;
            // TODO: Any outstanding reads or writes should be sent a "reset" response
            break;
        }

        // Fifth, check the ACK bit
        if (header.flags & ACK) {
            if (ack_num.InRange(m_tcb.SND.UNA, m_tcb.SND.NXT, LowerOpen {})) {
                // Enter Established State
                m_tcb.state = State::ESTABLISHED;

                m_tcb.SND.WND = header.window_size;
                m_tcb.SND.WL1 = seq_num;
                m_tcb.SND.WL2 = ack_num;
            } else {
                // Otherwise, send a RST segment with sequence number = incoming ack number
                SendTCPPacket(RST, {}, ack_num.Get());
                break;
            }
        } else {
            // If it isn't set, drop the segment and return
            break;
        }

        // 6 and 7 don't apply to SYN-RCVD

        // Eighth, check the FIN bit
        if (header.flags & FIN) {
            // Todo: Signal to the user that the connection is closing, exit any pending reads

            // Advance RCV.NXT over the fin
            m_tcb.RCV.NXT = seq_num + segment_length + 1;

            // Send an ACK for the FIN
            SendTCPPacket(ACK, {}, m_tcb.SND.NXT.Get(), m_tcb.RCV.NXT.Get());

            // Enter the CLOSE-WAIT state
            m_tcb.state = State::CLOSE_WAIT;
        }

        // FIXME: Alert the parent socket that a new connection has been established if this connection
        //        was created through passive open
        break;
    }
    default: {
        // In the RFC, this is the handling 3.10.7.4 Other States, excluding SYN_RCVD

        // Same logic for part 1 in all States
        bool valid = ValidateSequenceNumber(segment_length, seq_num);

        if (!valid) {
            if (header.flags & RST) {
#ifdef DEBUG_TCP
                std::cerr << "Dropping packet due to RST and invalid seq_num for tcb" << std::endl;
#endif
                break;
            }

            SendTCPPacket(ACK, {}, m_tcb.SND.NXT.Get(), m_tcb.RCV.NXT.Get());

            // After sending ACK drop the packet and return
#ifdef DEBUG_TCP
            std::cerr << "Dropping packet due to invalid seq_num for tcb" << std::endl;
#endif
            break;
        }

        if (seq_num != m_tcb.RCV.NXT) {
            // If we are not expecting this sequence number, just drop it
            // FIXME: We should queue this for later processing
            break;
        }

        // Second, check the reset bit
        if (header.flags & RST) {
            if (getState() == State::ESTABLISHED || getState() == State::FIN_WAIT_1 ||
                getState() == State::FIN_WAIT_2 || getState() == State::CLOSE_WAIT) {
                // TODO: Send a reset signal to any outstanding read or write calls
            }

            m_tcb.state = State::CLOSED;
            m_manager->Unregister(this);
            break;
        }

        // Todo: Third, check security

        // Fourth, check the SYN bit. Same for all synchronized states
        if (header.flags & SYN) {
            // This is an error, send a reset
            // TODO: Send a reset signal to any outstanding read or write calls

            SendTCPPacket(RST, {});

            m_tcb.state = State::CLOSED;
            m_manager->Unregister(this);
        }

        // Fifth, check the ACK bit
        if (header.flags & ACK) {
            if (ack_num.InRange(m_tcb.SND.UNA, m_tcb.SND.NXT, LowerOpen{})) {
                // Todo: Remove any segments on the retransmission queue that are therefore ACKed
                // Todo: In addition alert the appropriate write calls that their data has been sent

                m_tcb.SND.UNA = ack_num;

                // Check if our fin is ACKED, only for states in the close sequence
                if (m_fin_sent && ack_num.InRange(m_fin_number, m_tcb.SND.NXT, LowerOpen{})) {
                    if (getState() == State::FIN_WAIT_1) {
                        m_tcb.state = State::FIN_WAIT_2;
                    } else if (getState() == State::CLOSING) {
                        m_tcb.state = State::TIME_WAIT;
                    } else if (getState() == State::LAST_ACK) {
                        // If our FIN is acked in this case, then we delete the TCB and close the connection
                        m_tcb.state = State::CLOSED;
                        m_manager->Unregister(this);
                    }

                    m_fin_acked = true;
                }

            } else if (ack_num.UnsafeGT(m_tcb.SND.NXT)) {
                // If our ACK is acking something that has not been sent yet, send an ACK and drop the segment
                // Fixme: This format might be wrong
                SendTCPPacket(ACK, {}, m_tcb.SND.NXT.Get(), m_tcb.RCV.NXT.Get());
                break;
            }

            if (ack_num.InRange(m_tcb.SND.UNA, m_tcb.SND.NXT, Closed{})) {
                // Then we should update the send window
                if (m_tcb.SND.WL1.UnsafeLT(seq_num) || (m_tcb.SND.WL1 == seq_num && m_tcb.SND.WL2.UnsafeLE(ack_num))) {
                    m_tcb.SND.WL1 = seq_num;
                    m_tcb.SND.WL2 = ack_num;
                    m_tcb.SND.WND = header.window_size;
                }
            }

            if (getState() == State::TIME_WAIT) {
                // FIXME: The only thing that can arrive in this state is a retransmission of the remote FIN.
                //  Acknowledge it, and restart the 2 MSL timeout.
            }

            if (getState() == State::FIN_WAIT_2) {
                // TODO: if the retransmission queue is empty, the user's CLOSE can be acknowledged ("ok")
                //  but do not delete the TCB.
            }
        } else {
            // Drop the packet
            break;
        }

        // Only handle URG Bit and Segment text in these states
        if (getState() == State::ESTABLISHED || getState() == State::FIN_WAIT_1 || getState() == State::FIN_WAIT_2) {
            // Sixth, check the URG bit
            if (header.flags & URG) {
                // Only handle URG bit for these states
                m_tcb.RCV.UP = std::max(m_tcb.RCV.UP, header.urgent_pointer.Convert());

                // Todo: Signal to the user that the remote has urgent data if the urgent pointer
                //      is ahead of the data currently being read, however if the user has already
                //      been signaled that there is urgent data, then do not notify them again
            }

            // Seventh, process the segment text
            if (segment_length != 0) {
                // FIXME: Thread safety
                if (m_receive_buffer.Write(buffer.GetPayload())) {
                    m_tcb.RCV.NXT += segment_length;
                    m_tcb.RCV.WND = m_receive_buffer.RemainingSpace();

                    // TODO: Delay ACKs if necessary
                    SendTCPPacket(ACK, {}, m_tcb.SND.NXT.Get(), m_tcb.RCV.NXT.Get());

                    if (header.flags & PSH) {
                        // TODO: The push flag means that it is now OK to send this data to the user
                        std::cout << "Pushing Data To Socket: " << std::endl;
                        auto read_buffer = m_receive_buffer.Read(m_receive_buffer.GetLength() - m_receive_buffer.RemainingSpace());
                        read_buffer.Hexdump();
                    }
                }
            }
        }

        if (header.flags & FIN) {
            // TODO: Signal connection closing to any pending reads
            // TODO: Also, this FIN implies header.flags & PSH, so push the data in the buffer

            switch (getState()) {
            case State::ESTABLISHED:
                m_tcb.state = State::CLOSE_WAIT;
                break;
            case State::FIN_WAIT_1:
                if (m_fin_acked) {
                    // TODO: Start the time wait timer, turn off other timers
                    m_tcb.state = State::TIME_WAIT;
                } else {
                    m_tcb.state = State::CLOSING;
                }
                break;
            case State::FIN_WAIT_2:
                // TODO: Start the time wait timer, turn off other timers
                m_tcb.state = State::TIME_WAIT;
                break;
            case State::TIME_WAIT:
                // TODO: Restart the 2 MSL timer
                break;
            default:
                // In all other cases, do nothing
                break;
            }
        }

        break;
    }
    }
}

bool TCPSocket::ValidateSequenceNumber(size_t segment_length, Modular<u32>& seq_num)
{
    bool valid = false;

    if (segment_length == 0 && m_tcb.RCV.WND == 0) {
        valid = seq_num == m_tcb.RCV.NXT;
    } else if (segment_length == 0 && m_tcb.RCV.WND > 0) {
        valid = seq_num.InRange(m_tcb.RCV.NXT, m_tcb.RCV.NXT + m_tcb.RCV.WND, UpperOpen {});
    } else if (segment_length > 0 && m_tcb.RCV.WND > 0) {
        valid = seq_num.InRange(m_tcb.RCV.NXT, m_tcb.RCV.NXT + m_tcb.RCV.WND, UpperOpen {})
            || (seq_num + segment_length - 1).InRange(m_tcb.RCV.NXT, m_tcb.RCV.NXT + m_tcb.RCV.WND, UpperOpen {});
    }

    return valid;
}
void TCPSocket::SendTCPPacket(u16 flags, std::optional<VLBuffer> maybe_data, u32 seq_num, u32 ack_num)
{
    using enum TCPHeader::Flags;

    size_t maybe_data_size = 0;
    if (maybe_data.has_value()) {
        maybe_data_size = maybe_data->Size();
    }
    NetworkBuffer buffer = m_general_config.BuildBuffer(m_tcp_config.LayerSize() + maybe_data_size);
    auto& tcp = buffer.AddLayer<LayerType::TCP>(m_tcp_config.LayerSize());
    m_tcp_config.ConfigureLayer(tcp);

    tcp.SetAckNum(ack_num);
    tcp.SetSeqNum(seq_num);
    tcp.SetWindow(m_tcb.RCV.WND);
    tcp.SetFlags(flags);

    if (maybe_data) {
        u8* data = buffer.GetPayload().Data();
        std::copy(maybe_data->Data(), maybe_data->Data() + maybe_data->Size(), data);
    }

    m_manager->SendPacket(std::move(buffer), m_connected_addr);
}

u32 TCPSocket::GenerateISS()
{
    // Fixme: This is what would be considered a worst practice. There is something
    //        in the RFC that says how to handle this
    return random();
}