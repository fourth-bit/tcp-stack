//
// Created by Ryan Wolk on 3/22/22.
//

#pragma once

#include <array>
#include <forward_list>
#include <future>
#include <list>
#include <optional>
#include <string>

#include "./Error.h"
#include "EthernetMAC.h"
#include "ICMPManager.h"
#include "IPv4Address.h"
#include "NetworkBuffer.h"
#include "NetworkOrder.h"
#include "Protocols.h"
#include "TCPManager.h"
#include "UDPManager.h"
#include "VLBuffer.h"

u16 IPv4Checksum(void* address, int num_bytes);
u32 IPv4ChecksumAdd(void* address, int count, u32 start = 0);
u16 IPv4ChecksumEnd(u32);

struct EthernetConnection {
    EthernetMAC source_mac;
    EthernetMAC destination_mac;
    u16 connection_type;

    NetworkBuffer BuildBufferWith(NetworkBufferConfig&, size_t) const;
};

struct IPv4Connection {
    EthernetConnection eth;
    IPv4Address connected_ip;
    IPv4Address our_ip;
    u32 id;
    u32 type_of_service;

    NetworkBuffer BuildBufferWith(NetworkBufferConfig&, size_t) const;
};

struct IPv4FragmentID {
    int id;
    IPv4Address address;

    bool operator==(const IPv4FragmentID&) const = default;
};

namespace std {
template <>
struct hash<IPv4FragmentID> {
    size_t operator()(const IPv4FragmentID& id) const
    {
        u64 value = id.id;
        value += (u64)id.address.GetAddress() << 32;

        return hash<u64> {}(value);
    }
};
}

class IPv4Fragments {
public:
    IPv4Fragments(size_t size, std::list<std::pair<std::chrono::steady_clock::time_point, IPv4FragmentID>>::iterator it)
        : m_it(it)
    {
        // Add original hole
        HoleDescriptor.push_back({
            0,
            USHRT_MAX,
        });
    }
    IPv4Fragments(IPv4Fragments&&) = default;
    IPv4Fragments& operator=(IPv4Fragments&&) = default;
    ~IPv4Fragments()
    {
        if (header) {
            free(header);
        }
    }

    void CopyInHeader(const IPv4Header&);
    bool AddFragment(NetworkBuffer data);

    auto GetQueueIt() const { return m_it; }

    bool IsFull() const;
    NetworkBuffer Release();

private:
    struct Hole {
        u16 fragment_first;
        u16 fragment_last;
    };

    struct Fragment {
        NetworkBuffer fragmentData;
        u16 offset;
    };

    IPv4Header* header { nullptr };
    std::list<Hole> HoleDescriptor;
    std::list<Fragment> FragmentList {};
    size_t total_bytes_filled { 0 };

    std::list<std::pair<std::chrono::steady_clock::time_point, IPv4FragmentID>>::iterator m_it;
};

class NetworkDevice {
public:
    NetworkDevice(EthernetMAC mac_address,
        IPv4Address ip_str,
        u8 subnet,
        IPv4Address router,
        size_t MTU = 1500);
    ~NetworkDevice() noexcept;

    void Listen();

    void SendIPv4(NetworkBuffer data, IPv4Address, IPv4Header::ProtocolType);
    void SendEthernet(NetworkBuffer data, EthernetMAC, u16 protocol);

    std::optional<EthernetMAC> SendArp(IPv4Address target);

    ARPBuffer MakeARPBuffer(size_t payload_size);
    IPv4Buffer MakeIPv4Buffer(size_t payload_size);

    std::optional<IPv4Connection> MakeIPConnection(IPv4Address);

    ICMPManager& GetICMPManager() { return icmpManager; };
    UDPManager& GetUDPManager() { return udpManager; }
    TCPManager& GetTCPManager() { return tcpManager; }

    EthernetConnection FlipConnection(const EthernetConnection&);
    IPv4Connection FlipConnection(const IPv4Connection&);

    const size_t& GetMTU() const { return MTU; }
    const EthernetMAC& GetMac() const { return mac; }
    const IPv4Address& GetIPAddress() const { return ip; }
    const IPv4Address& GetGateway() const { return m_router; }
    const SubnetMask& GetSubnetMask() const { return subnet_mask; }
    const NetworkBufferConfig& GetIPv4Config() const { return m_default_ip4_config; }

private:
    void ResolveARP(NetworkBuffer&, EthernetConnection&);
    void ResolveIPv4(NetworkBuffer&, EthernetConnection&);

    void IPTimeoutFunction(std::stop_token);

    struct Route {
        EthernetMAC dest_mac;
        IPv4Address dest_addr;
    };

    static std::optional<Route> MakeRoutingDecision(IPv4Address);

    int tun_fd;
    int m_thread_notify_fd;
    int m_thread_wakeup_fd;

    size_t MTU;
    IPv4Address ip;
    IPv4Address m_router;
    SubnetMask subnet_mask;
    EthernetMAC mac;

    NetworkBufferConfig m_arp_buffer_config;
    NetworkBufferConfig m_default_ip4_config;
    NetworkBufferConfig m_default_l1_config;

    std::unordered_map<u32, EthernetMAC> arp_translation_table {};
    std::unordered_map<IPv4Address, std::promise<void>, IPv4Hasher> m_arp_wait_map {};

    // TODO: Make class for IPv4/6
    std::mutex m_fragment_mutex;
    std::condition_variable m_fragment_timeout_cv;
    std::unordered_map<IPv4FragmentID, IPv4Fragments> m_ip_fragments;
    std::list<std::pair<std::chrono::steady_clock::time_point, IPv4FragmentID>> fragment_timeout_queue {};

    std::thread listen_thread;

    static constexpr std::chrono::milliseconds fragment_timeout_time { 5000 };

    ICMPManager icmpManager;
    UDPManager udpManager;
    TCPManager tcpManager;

    std::jthread fragment_timeout;
};

extern std::unique_ptr<NetworkDevice> the_net_dev;