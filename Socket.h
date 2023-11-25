//
// Created by Ryan Wolk on 4/30/22.
//

#pragma once

#include <condition_variable>
#include <list>
#include <memory>
#include <mutex>
#include <optional>
#include <queue>

#include "./Error.h"
#include "CircularBuffer.h"
#include "FIFOLock.h"
#include "IPv4Address.h"
#include "IntDefs.h"
#include "Modular.h"
#include "NetworkAddress.h"
#include "NetworkBuffer.h"
#include "Utils.h"
#include "VLBuffer.h"

class UDPManager;
class TCPManager;
struct TCPConnection;

enum class PROTOCOL {
    INTERNET,
    INTERNET6,
};

enum class SOCK_TYPE {
    STREAM,
    DATAGRAM,
    RAW
};

u8 socktype_to_ipproto(SOCK_TYPE);

struct SocketInfo {
    virtual PROTOCOL GetFamily() = 0;
    virtual ~SocketInfo() = default;
};

// Todo: Find a better name
struct PortSocketInfo : public SocketInfo {
    PortSocketInfo(const NetworkAddress& arg_address, u16 arg_port)
        : address(arg_address)
        , port(arg_port)
    {
    }

    PROTOCOL GetFamily() override { return PROTOCOL::INTERNET; }

    NetworkAddress address;
    u16 port;
};

class SocketError : public Error {
public:
    enum class Code {
        SimultaneousRead,
        ReadFromConnectionSocket,
        ReadFromClosedSocket,
        WriteToConnectionSocket,
        SimultaneousAccept,
        AcceptOnNonListeningSocket,
    };


    static std::unique_ptr<Error> Make(Code code, std::string information = "")
    {
        return std::unique_ptr<Error>(new SocketError(code, std::move(information)));
    }

    std::string ToString() override;

    Code code;
    std::string information;

private:
    SocketError(Code code, std::string information)
        : code(code)
        , information(std::move(information))
    {
    }
};

class Socket {
public:
    // No copy, no move
    Socket(const Socket&) = delete;
    Socket(Socket&&) = delete;

    static Socket* Create(PROTOCOL, SOCK_TYPE);
    virtual ~Socket() = default;

    virtual bool Connect(NetworkAddress, u16) = 0;
    virtual bool Bind(u16) = 0;
    virtual bool Listen() = 0;

    virtual ErrorOr<std::pair<Socket*, SocketInfo*>> Accept() = 0;

    virtual ErrorOr<VLBuffer> Read() = 0;
    virtual u64 Write(const VLBufferView) = 0;

    virtual bool Close() = 0;

protected:
    Socket() = default;
};

class UDPSocket : public Socket {
public:
    struct DatagramInfo {
        VLBuffer buffer;
        NetworkAddress addr;
        u16 port;
    };

    static std::optional<UDPSocket> To();
    UDPSocket(UDPManager*, const NetworkBufferConfig&, Badge<Socket>);
    ~UDPSocket() noexcept override;

    bool Connect(NetworkAddress, u16) override;
    bool Bind(u16) override;
    bool Listen() override;
    ErrorOr<std::pair<Socket*, SocketInfo*>> Accept() override;

    ErrorOr<VLBuffer> Read() override;
    u64 Write(const VLBufferView) override;

    ErrorOr<DatagramInfo> ReadFrom();
    u64 WriteTo(const VLBufferView, NetworkAddress, u16 port);

    bool ConnectionMatches(NetworkAddress, u16);
    void AppendReadPayload(VLBufferView, NetworkAddress, u16);

    bool Close() override;
    bool UnregisterSubsocket(UDPSocket* socket);

private:
    UDPSocket(UDPManager*, const NetworkBufferConfig&);

    struct UDPSockInfo {
        NetworkAddress address;
        u16 port;

        bool operator==(const UDPSockInfo& other) const
        {
            return (address == other.address) && (port == other.port);
        }
    };

    struct UDPSockInfoHasher {
        size_t operator()(const UDPSockInfo& info) const
        {
            NetworkAddressHasher hasher1 {};
            size_t hash1 = hasher1(info.address);

            std::hash<u16> hasher2 {};
            size_t hash2 = hasher2(info.port);

            return hash_combine(hash1, hash2);
        }
    };

    bool is_open { true };

    std::list<DatagramInfo> m_read_buffers;
    std::mutex write_lock;
    std::mutex read_lock;
    bool in_read { false };
    std::mutex read_cv_lock;
    std::condition_variable read_cv;

    // Todo: Figure out if these are necessary. Maybe not because read locks and accept locks are not used at the same time
    bool in_accept { false };
    std::mutex accept_lock;
    std::mutex accept_cv_lock;
    std::condition_variable accept_cv;

    bool has_written { false };
    u16 m_bound_port { 0 };
    std::tuple<NetworkAddress, u16, bool> m_connected_to;

    UDPManager* udpManager;
    const NetworkBufferConfig& m_general_config;
    UDPLayer::Config m_udp_config;

    bool is_listening { false };
    std::unordered_map<UDPSockInfo, UDPSocket*, UDPSockInfoHasher> m_listening_subsockets {};
    // Todo: Cap this, there is a reason for the argument in the listen syscall (DOS Attack)
    std::list<DatagramInfo> m_accept_backlog {};
    UDPSocket* parent { nullptr };
};

class TCPSocket : public Socket {
    friend class TCPManager;

    enum class State {
        CLOSED,
        LISTEN,
        SYN_SENT,
        SYN_RCVD,
        ESTABLISHED,
        CLOSE_WAIT,
        LAST_ACK,
        FIN_WAIT_1,
        FIN_WAIT_2,
        CLOSING,
        TIME_WAIT,
    };

    struct TCB {
        State state;

        // Receive portion of the TCB
        struct {
            // Receive Next
            Modular<u32> NXT { 0 };
            // Receive Window
            u16 WND { 0 };
            // Receive Urgent Pointer
            u16 UP { 0 };
            // Initial Receive Sequence Number
            Modular<u32> IRS { 0 };
        } RCV;

        // Send portion of the TCB
        struct {
            // Send Unacknowledged
            Modular<u32> UNA { 0 };
            // Send Next
            Modular<u32> NXT { 0 };
            // Send Window
            u16 WND { 0 };
            // Send Urgent Pointer
            u16 UP { 0 };
            // Segment Sequence Number Used For Last Window Update
            Modular<u32> WL1 { 0 };
            // Segment Acknowledgement Number Used For Last Window Update
            Modular<u32> WL2 { 0 };
            // Initial Send Sequence Number
            Modular<u32> ISS { 0 };
        } SND;
    };

    using TCPTimePoint = std::chrono::time_point<std::chrono::steady_clock>;

    struct UnackedPacket {
        VLBuffer data;
        Modular<u32> seq_num;
        std::optional<TCPTimePoint> send_timestamp;
        bool retransmitted { false };
    };


public:
    TCPSocket(TCPManager*, const NetworkBufferConfig&, PROTOCOL proto, Badge<Socket>);

    bool Connect(NetworkAddress, u16) override;
    bool Bind(u16) override;
    bool Listen() override;

    ErrorOr<std::pair<Socket*, SocketInfo*>> Accept() override;

    ErrorOr<VLBuffer> Read() override;
    u64 Write(const VLBufferView) override;

    bool Close() override;

    void HandleIncomingPacket(NetworkBuffer, TCPConnection);
    void SendTCPPacket(u16 flags, std::optional<VLBuffer> maybe_data, u32 seq_num = 0, u32 ack_num = 0);

    u32 GenerateISS();

    u16 GetPort() const { return m_bound_port; }

private:
    TCPSocket(TCPManager*, const NetworkBufferConfig&, PROTOCOL proto);

    State getState() const { return m_tcb.state; }
    bool ValidateSequenceNumber(size_t segment_length, Modular<u32>& seq_num);

    size_t getUsableWindow() { return (m_tcb.SND.UNA + m_tcb.SND.WND - m_tcb.SND.NXT).Get(); }
    void WriteImpl_nolock(VLBuffer);
    void DrainWriteBuffer_nolock();

    void RTTCallback(Modular<u32>);

    TCPManager* m_manager;
    PROTOCOL m_proto;
    const NetworkBufferConfig& m_general_config;
    TCPLayer::Config m_tcp_config;

    NetworkAddress m_connected_addr;
    u16 m_connected_port { 0 };

    TCB m_tcb;
    size_t MSS;

    u16 m_bound_port { 0 };

    std::mutex m_read_buffer_lock;
    CircularBuffer m_receive_buffer;
    size_t current_read_size { 0 };
    std::condition_variable m_read_cv;

    Modular<u32> m_fin_number { 0 };
    bool m_fin_sent { false };
    bool m_fin_acked { false };

    FIFOLock m_read_queue;

    std::queue<UnackedPacket> m_unacked_packets;
    // Using language from RFC 6298
    std::chrono::milliseconds m_RTO { 1000 };
    std::chrono::milliseconds m_SRTT { -1 };
    std::chrono::milliseconds m_RTTVAR { -1 };
    std::optional<int> m_retransmission_timer_fd;

    // Locks everything related to writing data: retransmission queue, nagle queue, etc.
    std::mutex m_write_lock;
    CircularBuffer m_write_buffer;
};