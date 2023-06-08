//
// Created by Ryan Wolk on 4/30/22.
//

#pragma once

#include <list>
#include <mutex>
#include <memory>
#include <optional>
#include <condition_variable>

#include "IPv4Address.h"
#include "IntDefs.h"
#include "NetworkBuffer.h"
#include "NetworkAddress.h"
#include "VLBuffer.h"
#include "Utils.h"
#include "./Error.h"

class UDPManager;

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
        WriteToConnectionSocket,
        SimultaneousAccept,
        AcceptOnNonListeningSocket,
    };


    static std::unique_ptr<Error> Make(Code code, std::string information = "")
    {
        return std::unique_ptr<Error>(new SocketError(code, std::move(information)));
    }

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
    static Socket* Create(PROTOCOL, SOCK_TYPE);
    virtual ~Socket() = default;

    virtual bool Connect(NetworkAddress, u16) = 0;
    virtual bool Bind(u16) = 0;
    virtual bool Listen() = 0;

    virtual ErrorOr<std::pair<Socket*, SocketInfo*>> Accept() = 0;

    virtual ErrorOr<VLBuffer> Read() = 0;
    virtual u64 Write(const VLBufferView) = 0;

    virtual bool Close() = 0;
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
