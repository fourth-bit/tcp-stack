//
// Created by Ryan Wolk on 4/30/22.
//

#include <cassert>
#include <iostream>
#include <sstream>

#include "Badge.h"
#include "NetworkDevice.h"
#include "Socket.h"
#include "UDPManager.h"

struct Route {
    EthernetMAC targetMAC;
    IPv4Address next_hop;
};

u8 socktype_to_ipproto(SOCK_TYPE type)
{
    switch (type) {
    case SOCK_TYPE::STREAM:
        return IPPROTO_TCP;
    case SOCK_TYPE::DATAGRAM:
        return IPPROTO_UDP;
    case SOCK_TYPE::RAW:
        return IPPROTO_RAW;
    }
}

template <typename T>
struct is_chrono_duration {
    static constexpr bool value = false;
};
template <typename T, typename U>
struct is_chrono_duration<std::chrono::duration<T, U>> {
    static constexpr bool value = true;
};
template <typename T>
concept chrono_duration = is_chrono_duration<T>::value;

template <chrono_duration T>
T chrono_lerp(T t1, T t2, double factor)
{
    return T((typename T::rep)((1 - factor) * t1.count() + factor * t2.count()));
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
        config = &the_net_dev->GetIPv6Config();

        // Sanity Check
        if (!config->HasLayer<LayerType::IPv6>()) {
            std::cerr << "Fatal: Malformed IPv4 Buffer Config in the_net_dev" << std::endl;
            assert(false);
        }
    }

    if (config == nullptr) {
        std::cerr << "Null NetworkBufferConfig in Socket::Create" << std::endl;
        return nullptr;
    }

    if (type == SOCK_TYPE::STREAM) {
        std::shared_ptr<TCPSocketBackend> backend = std::make_shared<TCPSocketBackend>(
            &the_net_dev->GetTCPManager(),
            *config,
            proto,
            Badge<Socket> {});

        return new TCPSocket(backend);
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

    return { Route {
        *result,
        to,
    } };
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

    std::unique_lock lock(read_lock);
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
    std::unique_lock lock(read_lock);
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
    if (std::get<2>(m_connected_to) && (in_addr != std::get<0>(m_connected_to) || in_port != std::get<1>(m_connected_to))) {
        // This socket is listening for a specifc connection, and this is not it
        return;
    }

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

    std::unique_lock lock(accept_lock);
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

    m_listening_subsockets[UDPSockInfo { in_addr, in_port }] = socket;
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

TCPSocketBackend::TCPSocketBackend(TCPManager* manager, const NetworkBufferConfig& config, PROTOCOL proto, Badge<Socket>)
    : TCPSocketBackend(manager, config, proto)
{
}
TCPSocketBackend::TCPSocketBackend(TCPManager* manager, const NetworkBufferConfig& config, PROTOCOL proto, Badge<TCPSocketBackend>)
    : TCPSocketBackend(manager, config, proto)
{
}
TCPSocketBackend::TCPSocketBackend(TCPManager* manager, const NetworkBufferConfig& config, PROTOCOL proto)
    : m_manager(manager)
    , m_general_config(config)
    , m_tcb { .state = State::CLOSED }
    , m_receive_buffer(65535)
    , m_write_buffer(65535)
    , m_proto(proto)
{
    switch (m_proto) {
    case PROTOCOL::INTERNET:
        MSS = 536;
        break;
    case PROTOCOL::INTERNET6:
        MSS = 1220;
        break;
    }
}

bool TCPSocketBackend::Connect(NetworkAddress connected_address, u16 connected_port)
{
    // This call only makes sense in a not yet open socket
    if (getState() != State::CLOSED) {
        return false;
    }

    if (m_bound_port == 0) {
        auto port = m_manager->ReserveEphemeral(shared_from_this());
        if (!port.has_value()) {
            return false;
        }

        m_bound_port = *port;
        m_tcp_config.source_port = m_bound_port;
    }

    bool registered = m_manager->RegisterConnection(shared_from_this(), TCPConnection { connected_address, connected_port, m_bound_port });
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
bool TCPSocketBackend::Bind(u16 port)
{
    if (m_bound_port != 0) {
        return false;
    }

    bool res = m_manager->ReservePort(shared_from_this(), port);
    if (res) {
        m_bound_port = port;
        m_tcp_config.source_port = m_bound_port;

        return true;
    }

    return false;
}
bool TCPSocketBackend::Listen()
{
    bool res = m_manager->RegisterListening(shared_from_this());

    if (!res) {
        return false;
    }

    m_tcb.state = State::LISTEN;

    return true;
}
ErrorOr<std::pair<Socket*, SocketInfo*>> TCPSocketBackend::Accept()
{
    if (m_tcb.state != State::LISTEN) {
        return SocketError::Make(SocketError::Code::AcceptOnNonListeningSocket);
    }

    std::unique_lock lock1(m_accept_queue);

    std::unique_lock lock2(m_accept_lock);
    if (m_accept_backlog.empty()) {
        m_accept_cv.wait(lock2, [this]() { return !m_accept_backlog.empty(); });
    }

    TCPSocket* socket = m_accept_backlog.front().release();
    m_accept_backlog.pop_front();

    SocketInfo* info = new PortSocketInfo {
        socket->m_backend->m_connected_addr,
        socket->m_backend->m_connected_port,
    };

    return { { dynamic_cast<Socket*>(socket), info } };
}
ErrorOr<VLBuffer> TCPSocketBackend::Read()
{
    if (m_tcb.state == State::CLOSED) {
        return SocketError::Make(SocketError::Code::ReadFromClosedSocket);
    } else if (m_tcb.state == State::LISTEN) {
        return SocketError::Make(SocketError::Code::ReadFromConnectionSocket);
    }

    // Grab the lock first for proper queueing
    std::unique_lock lock1(m_read_queue);

    // Now only the Read method and HandleIncoming can get their hands on this lock
    std::unique_lock lock2(m_read_buffer_lock);

    m_read_cv.wait(lock2, [this]() {
        return m_receive_buffer.GetUsedLength() != 0 || m_remote_closing;
    });

    if (m_receive_buffer.GetUsedLength() == 0 && m_remote_closing) {
        return SocketError::Make(SocketError::Code::ConnectionClosing);
    }

    auto ret = m_receive_buffer.Read(m_receive_buffer.GetUsedLength());

    return ret;
}
u64 TCPSocketBackend::Write(VLBufferView data)
{
    /* Write is the public interface to writing data to the socket. All this function
     * is responsible for is to put data in the write_buffer, and if we can't block
     * until we can.
     */

    {
        std::scoped_lock lock(m_tcb_lock);
        // Stop data from being sent when we don't want it. Makes some state based
        // logic easier if we don't have pending sends in SYN_RCVD for closing the socket.
        // Also prevent WRITEs in the case that we are blocking on data being sent in CLOSE,
        // but we haven't officially sent a FIN
        if (data.Size() == 0
            || (m_tcb.state != State::ESTABLISHED && m_tcb.state != State::CLOSE_WAIT)
            || m_client_closing) {
            return 0;
        }
    }

    /* How do we want the data to actually send?
     *  1: When is it proper to send data?
     *      We can send data if a full sized segment fits in the window (and we
     *      have enough data to fill a full sized segment), or wait until all
     *      UNACKED packets have been ACKED. Otherwise, block and queue the data
     *  2: Whose responsibility is it to make a packet?
     *      The crux of the question is when we have multiple packets in the queue,
     *      who has to call SendTCPPacket? The idea is that we can call SendTCPPacket
     *      piggybacked with an ACK for when the unacked data clears. This logic is theory
     *      happens in and around the HandleIncoming logic, the exact method is TBD, and likely
     *      has something to do with delayed ACKs.
     */

    size_t data_written = 0;

    {
        std::scoped_lock lock(m_write_lock);

        // In this case, we can bypass the write buffer
        if (m_tcb.SND.UNA == m_tcb.SND.NXT && m_write_buffer.GetUsedLength() == 0 && getUsableWindow() >= MSS) {
            // Send an MSS sized segment
            size_t write_size = std::min(data.Size(), MSS);

            WriteImpl_nolock(data.ShrinkEnd(write_size).CopyToVLBuffer());
            data = data.SubBuffer(write_size);
            data_written += write_size;
        }

        if (data.Size() > 0) {
            // We need to buffer the data if it can't be written immediately
            size_t buffer_write_size = std::min(m_write_buffer.RemainingSpace(), data.Size());
            data_written += buffer_write_size;
            if (data_written == 0) {
                // TODO: Block until there is space ...
                return -1;
            }

            m_write_buffer.Write(data.ShrinkEnd(buffer_write_size));

            DrainWriteBuffer_nolock();
        }
    }

    return data_written;
}

void TCPSocketBackend::WriteImpl_nolock(VLBuffer data)
{
    size_t packet_len = data.Size();
    SendTCPPacket(TCPHeader::PSH | TCPHeader::ACK, data.Copy(), m_tcb.SND.NXT.Get(), m_tcb.RCV.NXT.Get());
    m_unacked_packets.emplace(std::move(data), m_tcb.SND.NXT, TCPTimePoint::clock::now());

    // (RFC 6298) 5. Managing the RTO Timer
    // 5.1 Start the timer on packet send, if the timer is not running
    if (!m_retransmission_timer_fd.has_value()) {
        Modular<u32> sent_seq_num = m_tcb.SND.NXT;
        m_retransmission_timer_fd = m_manager->GetRetransmissionTimers().AddTimer(
            m_RTO,
            [this, sent_seq_num]() { RTTCallback(sent_seq_num); });
    }

    m_tcb.SND.NXT += packet_len;
}

void TCPSocketBackend::DrainWriteBuffer_nolock()
{
    if (m_tcb.SND.UNA == m_tcb.SND.NXT && getUsableWindow() >= m_write_buffer.GetUsedLength() && m_write_buffer.GetUsedLength() <= MSS) {
        // Send a packet with <= MSS size if and only if no unacked data and there is window space
        WriteImpl_nolock(m_write_buffer.Read(m_write_buffer.GetUsedLength()));
    }

    while (m_write_buffer.GetUsedLength() >= MSS && getUsableWindow() >= MSS) {
        WriteImpl_nolock(m_write_buffer.Read(MSS));
    }

    if (m_client_closing && m_write_buffer.Empty()) {
        m_close_cv.notify_all();
    }
}

bool TCPSocketBackend::Close()
{
    return Close(false);
}

bool TCPSocketBackend::Close(bool ignore_already_closing)
{
    using enum TCPHeader::Flags;

    // FIXME: Grab the correct locks for this
    std::unique_lock lock(m_tcb_lock);

    if (m_client_closing && !ignore_already_closing) {
        // Stop us from closing twice
        return false;
    }

    m_client_closing = true;

    // In Closing send relevant signals to condition variables
    switch (m_tcb.state) {
    case State::CLOSED:
        return false;
    case State::LISTEN:
        return m_manager->Unregister(shared_from_this());
    case State::SYN_SENT:
        return m_manager->Unregister(shared_from_this());
    case State::SYN_RCVD:
        // Because we disallow sends in SYN_RCVD, the logic is much simpler
        // to implement to spec

        SendTCPPacket(FIN | ACK, {}, m_tcb.SND.NXT.Get(), m_tcb.RCV.NXT.Get());
        m_unacked_packets.push(UnackedPacket {
            .data = VLBuffer::WithSize(0),
            .seq_num = m_tcb.SND.NXT,
            .send_timestamp = TCPTimePoint::clock::now(),
            .is_fin = true,
        });
        m_fin_sent = true;
        m_fin_number = m_tcb.SND.NXT;
        m_tcb.SND.NXT += 1;
        m_tcb.state = State::FIN_WAIT_1;
        break;
    case State::ESTABLISHED:
    case State::CLOSE_WAIT:
        // Slightly different here in the state transition
        // Anyway, block until all sent data has been properly processed
        // The send logic requires the tcb lock, so it makes sense to wait
        // with it

        if (!m_write_buffer.Empty()) {
            m_close_cv.wait(lock);

            // Now that we've waited, the state may have changed, so our actions
            // logically should change
            lock.unlock();
            return Close(true);
        } else {
            SendTCPPacket(FIN | ACK, {}, m_tcb.SND.NXT.Get(), m_tcb.RCV.NXT.Get());
            m_unacked_packets.push(UnackedPacket {
                .data = VLBuffer::WithSize(0),
                .seq_num = m_tcb.SND.NXT,
                .send_timestamp = TCPTimePoint::clock::now(),
                .is_fin = true,
            });
            m_fin_sent = true;
            m_fin_number = m_tcb.SND.NXT;
            m_tcb.SND.NXT += 1;

            // Here is where it diverges in the spec
            if (m_tcb.state == State::ESTABLISHED) {
                m_tcb.state = State::FIN_WAIT_1;
            } else {
                m_tcb.state = State::LAST_ACK;
            }
        }
        break;
    default:
        return false;
    }

    return true;
}

void TCPSocketBackend::HandleIncomingPacket(NetworkBuffer buffer, TCPConnection connection)
{
    // FIXME: RFC 5961 Recommendations

    using enum TCPHeader::Flags;
    using namespace std::chrono_literals;

    // For simplicity, grab all locks at the beginning
    std::unique_lock tcb_lock(m_tcb_lock, std::defer_lock);
    std::unique_lock read_lock(m_read_buffer_lock, std::defer_lock);
    std::unique_lock write_lock(m_write_lock, std::defer_lock);
    std::lock(tcb_lock, read_lock, write_lock);

    auto* tcp_layer = buffer.GetLayer<LayerType::TCP>();
    if (tcp_layer == nullptr) {
        std::cerr << "Error: Invalid Buffer Passed to TCPSocket::HandleIncomingPacket" << std::endl;
        return;
    }

    auto& header = tcp_layer->GetHeader();
    size_t segment_length = buffer.GetPayload().Size();
    Modular<u32> seq_num = header.seq_num.Convert();
    Modular<u32> ack_num = header.ack_num.Convert();

    // Parse Options
    if (header.header_length * 4 > sizeof(TCPHeader)) {
        // Then, there are options
        size_t options_length = header.header_length * 4 - sizeof(TCPHeader);
        size_t i = 0;
        while (i < options_length) {
            // Parse the options kind
            u8 kind = header.options[i];

            bool is_end = false;

            switch (kind) {
            case 0:
                // End-Of-Options List
                is_end = true;
                break;
            case 1:
                // No-Op
                i++;
                break;
            case 2: {
                // Maximum-Segment Size Option
                // Next octet is length

                u8 option_length = header.options[i + 1];
                if (option_length != 4) {
                    // FIXME: What should we do? Send a RST? Ignore it?
                    break;
                }

                // Pointer Crimes to parse this as a network ordered u16, don't let the MSS increase either
                MSS = std::min((size_t)NetworkOrdered(*(u16*)(header.options + (i + 2))).Convert(), MSS);

                i += option_length;
                break;
            }
            default: {
                // Read the length octet
                u8 option_length = header.options[i + 1];

                // Ignore the data
                i += option_length;

                if (option_length == 0) {
                    // Fixme: What do we do here? Otherwise we would loop forever. Send a RST maybe?
                    is_end = true;
                    break;
                }
            }
            }

            if (is_end) {
                break;
            }
        }
    }

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

            auto new_socket_backend = std::make_shared<TCPSocketBackend>(m_manager, m_general_config, m_proto, Badge<TCPSocketBackend> {});

            // Setup TCB according to spec
            new_socket_backend->m_tcb.RCV.IRS = header.seq_num.Convert();
            new_socket_backend->m_tcb.RCV.NXT = header.seq_num + 1;
            new_socket_backend->m_tcb.RCV.WND = new_socket_backend->m_receive_buffer.RemainingSpace();
            new_socket_backend->m_tcb.SND.ISS = GenerateISS();
            new_socket_backend->m_tcb.SND.NXT = new_socket_backend->m_tcb.SND.ISS + 1;
            new_socket_backend->m_tcb.SND.UNA = new_socket_backend->m_tcb.SND.ISS;

            // Fixme: Fill in information about the connected party
            new_socket_backend->m_bound_port = m_bound_port;
            new_socket_backend->m_connected_addr = connection.connected_addr;
            new_socket_backend->m_connected_port = connection.connected_port;

            new_socket_backend->m_tcp_config.source_port = m_bound_port;
            new_socket_backend->m_tcp_config.dest_port = connection.connected_port;

            m_manager->AlertOpenConnection(shared_from_this(), new_socket_backend, connection);

            new_socket_backend->SendTCPPacket(SYN | ACK, {}, new_socket_backend->m_tcb.SND.ISS.Get(), new_socket_backend->m_tcb.RCV.NXT.Get());
            new_socket_backend->m_tcb.state = State::SYN_RCVD;

            std::unique_lock lk (m_accept_lock);
            m_accept_backlog.push_back(std::make_unique<TCPSocket>(new_socket_backend));
            lk.unlock();
            m_accept_cv.notify_one();
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
            m_manager->Unregister(shared_from_this());
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
            m_manager->Unregister(shared_from_this());
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
            if (getState() == State::ESTABLISHED || getState() == State::FIN_WAIT_1 || getState() == State::FIN_WAIT_2 || getState() == State::CLOSE_WAIT) {
                // TODO: Send a reset signal to any outstanding read or write calls
            }

            m_tcb.state = State::CLOSED;
            m_manager->Unregister(shared_from_this());
            break;
        }

        // Todo: Third, check security

        // Fourth, check the SYN bit. Same for all synchronized states
        if (header.flags & SYN) {
            // This is an error, send a reset
            // TODO: Send a reset signal to any outstanding read or write calls

            SendTCPPacket(RST, {});

            m_tcb.state = State::CLOSED;
            m_manager->Unregister(shared_from_this());
        }

        // Fifth, check the ACK bit
        if (header.flags & ACK) {
            if (ack_num.InRange(m_tcb.SND.UNA, m_tcb.SND.NXT, LowerOpen {})) {
                bool was_data_acked = false;

                while (!m_unacked_packets.empty()) {
                    auto& unacked_packet = m_unacked_packets.front();
                    auto awaiting_ack = unacked_packet.seq_num;

                    if (awaiting_ack.InRange(m_tcb.SND.UNA, ack_num, UpperOpen {})) {
                        if (!unacked_packet.retransmitted && unacked_packet.send_timestamp.has_value()) {
                            auto now = TCPTimePoint::clock::now();
                            auto sample = duration_cast<std::chrono::milliseconds>(now - *unacked_packet.send_timestamp);

                            // Assume millisecond precision
                            constexpr std::chrono::milliseconds G { 1 };
                            constexpr int K = 4;
                            constexpr double ALPHA = 1.0 / 8.0;
                            constexpr double BETA = 1.0 / 4.0;

                            if (m_SRTT == -1ms) {
                                // Then no samples have been taken
                                // RFC 6298 2.2
                                m_SRTT = sample;
                                m_RTTVAR = sample / 2;
                                m_RTO = m_SRTT + std::max(G, K * m_RTTVAR);
                            } else {
                                // RFC 6298 2.3

                                // Absolute value without having to deal with absolute value
                                if (m_SRTT > sample) {
                                    m_RTTVAR = chrono_lerp(m_RTTVAR, m_SRTT - sample, BETA);
                                } else {
                                    m_RTTVAR = chrono_lerp(m_RTTVAR, sample - m_SRTT, BETA);
                                }
                                m_SRTT = chrono_lerp(m_SRTT, sample, ALPHA);
                                m_RTO = m_SRTT + std::max(G, K * m_RTTVAR);
                            }

                            // When RTO is calculated, if it is less than 1 second, bound it to 1 second
                            if (m_RTO < 1s) {
                                m_RTO = 1s;
                            }
                        }

                        m_unacked_packets.pop();
                        was_data_acked = true;
                    } else {
                        break;
                    }
                }

                m_tcb.SND.UNA = ack_num;

                if (m_tcb.SND.UNA == m_tcb.SND.NXT) {
                    // All data has been ACKED
                    // (RFC 6298) 5.2 Turn off the RTT
                    if (m_retransmission_timer_fd.has_value()) {
                        m_manager->GetRetransmissionTimers().RemoveTimer(*m_retransmission_timer_fd);
                        m_retransmission_timer_fd = {};
                    }

                    // And we now have some data to send
                    if (m_write_buffer.GetUsedLength() != 0) {
                        DrainWriteBuffer_nolock();
                    }
                } else if (was_data_acked) {
                    // (RFC 6298) 5.3 If we ACKED some data, but not all of it, reset the RTT
                    if (m_retransmission_timer_fd.has_value()) {
                        m_manager->GetRetransmissionTimers().RemoveTimer(*m_retransmission_timer_fd);
                    }

                    if (!m_unacked_packets.empty()) {
                        Modular<u32> next_retrans_seq = m_unacked_packets.front().seq_num;

                        m_retransmission_timer_fd = m_manager->GetRetransmissionTimers().AddTimer(
                            m_RTO,
                            [this, next_retrans_seq]() { RTTCallback(next_retrans_seq); });
                    } else {
                        // CONTROL SHOULD NOT REACH HERE, THIS MEANS THAT WE THINK THERE
                        // IS DATA LEFT TO ACK, BUT WE HAVE NO RECORD OF THOSE PACKETS
                        assert(false);
                    }
                }

                // Check if our fin is ACKED, only for states in the close sequence
                if (m_fin_sent && ack_num.InRange(m_fin_number, m_tcb.SND.NXT, LowerOpen {})) {
                    if (getState() == State::FIN_WAIT_1) {
                        m_tcb.state = State::FIN_WAIT_2;
                    } else if (getState() == State::CLOSING) {
                        m_tcb.state = State::TIME_WAIT;
                    } else if (getState() == State::LAST_ACK) {
                        // If our FIN is acked in this case, then we delete the TCB and close the connection
                        m_tcb.state = State::CLOSED;
                        m_manager->Unregister(shared_from_this());
                    }

                    m_fin_acked = true;
                }

            } else if (ack_num.UnsafeGT(m_tcb.SND.NXT)) {
                // If our ACK is acking something that has not been sent yet, send an ACK and drop the segment
                // Fixme: This format might be wrong
                SendTCPPacket(ACK, {}, m_tcb.SND.NXT.Get(), m_tcb.RCV.NXT.Get());
                break;
            }

            if (ack_num.InRange(m_tcb.SND.UNA, m_tcb.SND.NXT, Closed {})) {
                // Then we should update the send window
                if (m_tcb.SND.WL1.UnsafeLT(seq_num) || (m_tcb.SND.WL1 == seq_num && m_tcb.SND.WL2.UnsafeLE(ack_num))) {
                    m_tcb.SND.WL1 = seq_num;
                    m_tcb.SND.WL2 = ack_num;
                    m_tcb.SND.WND = header.window_size;
                }
            }

            // Here because it says so in RFC, but handled later
            // if (getState() == State::TIME_WAIT) {
            // The only thing that can arrive in this state is a retransmission of the remote FIN.
            // Acknowledge it, and restart the 2 MSL timeout.
            // Handled in the FIN if statment
            // }

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

            // Seventh, process the segment text. FIXME: zero window probes
            if (segment_length != 0) {
                if (m_receive_buffer.Write(buffer.GetPayload())) {
                    m_tcb.RCV.NXT += segment_length;
                    m_tcb.RCV.WND = m_receive_buffer.RemainingSpace();

                    // TODO: Delay ACKs if necessary
                    SendTCPPacket(ACK, {}, m_tcb.SND.NXT.Get(), m_tcb.RCV.NXT.Get());

                    // Allow a waiting thread to read
                    m_read_cv.notify_one();
                }
            }
        }

        if (header.flags & FIN) {
            switch (getState()) {
            case State::ESTABLISHED:
                m_tcb.state = State::CLOSE_WAIT;
                goto ack_fin;
            case State::FIN_WAIT_1:
                if (m_fin_acked) {
                    EnterTimeWait_nolock();
                } else {
                    m_tcb.state = State::CLOSING;
                }
                goto ack_fin;
            case State::FIN_WAIT_2:
            case State::TIME_WAIT:
                EnterTimeWait_nolock();
                goto ack_fin;

            ack_fin:
                m_tcb.RCV.NXT += 1;
                SendTCPPacket(ACK, {}, m_tcb.SND.NXT.Get(), m_tcb.RCV.NXT.Get());
                break;

            default:
                // In all other cases, do nothing
                break;
            }

            m_remote_closing = true;
            m_read_cv.notify_all();
        }

        // If we have any unsent data, and now we have window, send the data
        // FIXME: Correct implementation of Nagle's Algorithm
        if (m_tcb.SND.UNA == m_tcb.SND.NXT && m_write_buffer.GetUsedLength() != 0) {
            size_t write_size = std::min(std::min(m_write_buffer.GetUsedLength(), getUsableWindow()), MSS);
            WriteImpl_nolock(m_write_buffer.Read(write_size));
        }

        break;
    }
    }
}

bool TCPSocketBackend::ValidateSequenceNumber(size_t segment_length, Modular<u32>& seq_num)
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
void TCPSocketBackend::SendTCPPacket(u16 flags, std::optional<VLBuffer> maybe_data, u32 seq_num, u32 ack_num)
{
    using enum TCPHeader::Flags;

    size_t maybe_data_size = 0;
    if (maybe_data.has_value()) {
        maybe_data_size = maybe_data->Size();
    }

    TCPLayer::Config config = m_tcp_config;

    // Send an MSS option on all SYN Segments
    if (flags & SYN) {
        config.MSS_option = MSS;
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

u32 TCPSocketBackend::GenerateISS()
{
    // Fixme: This is what would be considered a worst practice. There is something
    //        in the RFC that says how to handle this
    return random();
}

void TCPSocketBackend::RTTCallback(Modular<u32> seq_num)
{
    using namespace std::chrono_literals;
    // Steps from RFC 6298

    // Lock for the retransmission queue
    std::scoped_lock lock(m_write_lock);

    // Possible race condition: Segment arrives when RTT timer goes off
    // While executing HandleIncoming, the locks are taken, so when we get
    // here the outstanding packet has been ACKED, and the RTT reset, so
    // how can we differentiate between that RTT and the one where nothing
    // has arrived?

    if (m_unacked_packets.empty()) {
        // This means that the above condition happened
        return;
    }

    auto& unacked_packet = m_unacked_packets.front();

    if (unacked_packet.seq_num != seq_num) {
        // This means that the packet we are supposed to be retransmitting has
        // been ACKED in the time it took to get the lock, meaning the above
        // condition happened
        return;
    }

    // 5.4 Retransmit the last segment
    unacked_packet.retransmitted = true;
    if (!unacked_packet.is_fin) {
        SendTCPPacket(TCPHeader::PSH | TCPHeader::ACK, unacked_packet.data.Copy(), unacked_packet.seq_num.Get(), m_tcb.RCV.NXT.Get());
    } else {
        SendTCPPacket(TCPHeader::FIN | TCPHeader::ACK, {}, unacked_packet.seq_num.Get(), m_tcb.RCV.NXT.Get());
    }

    Modular<u32> transmitted_seq_num = unacked_packet.seq_num;

    // 5.5 Exponential backing on the RTO
    m_RTO *= 2;
    // 2.5 MAY place an upper limit on the RTO, of at least 60 seconds
    if (m_RTO >= 60s) {
        m_RTO = 60s;
    }

    // 5.6 Restart the RTT with new timeout
    m_retransmission_timer_fd = m_manager->GetRetransmissionTimers().AddTimer(
        m_RTO,
        [this, transmitted_seq_num]() { RTTCallback(transmitted_seq_num); });
}

void TCPSocketBackend::EnterTimeWait_nolock()
{
    m_tcb.state = State::TIME_WAIT;

    // Start a 2 MSL Timer, disable all other timers
    if (m_retransmission_timer_fd.has_value()) {
        m_manager->GetRetransmissionTimers().RemoveTimer(*m_retransmission_timer_fd);
    }

    int fd = m_manager->GetRetransmissionTimers().AddTimer(2 * m_RTO, [this] {
        // I'm worried about what could happen if this gets deallocated during the callback
        // as capturing this is a weak reference
        auto shared_this = shared_from_this();

        // When this timer expires, we delete the TCB, and close the connection
        m_tcb.state = State::CLOSED;
        m_manager->Unregister(shared_from_this());
    });

    m_retransmission_timer_fd = fd;
}