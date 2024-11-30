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
#include "ICMPv6Manager.h"
#include "IPv4Address.h"
#include "NetworkBuffer.h"
#include "NetworkOrder.h"
#include "Protocols.h"
#include "TCPManager.h"
#include "UDPManager.h"
#include "VLBuffer.h"

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

    NetworkConnection ToNetworkConnection() const;
};

struct PacketFragmentID {
    int id;
    NetworkAddress address;

    bool operator==(const PacketFragmentID&) const = default;
};

namespace std {
template <>
struct hash<PacketFragmentID> {
    size_t operator()(const PacketFragmentID& id) const
    {
        return hash_combine(std::hash<int> {}(id.id), addr_hash(id.address));
    }

    NetworkAddressHasher addr_hash {};
};
}

class PacketFragments {
    struct Hole {
        u16 fragment_first;
        u16 fragment_last;
    };

    struct Fragment {
        NetworkBuffer fragmentData;
        u16 offset;
    };

public:
    explicit PacketFragments(std::list<std::pair<std::chrono::steady_clock::time_point, PacketFragmentID>>::iterator it)
        : m_it(it)
    {
        // Add original hole
        HoleDescriptor.push_back({
            0,
            USHRT_MAX,
        });
    }
    virtual ~PacketFragments() = default;

    PacketFragments(PacketFragments&&) = default;
    PacketFragments& operator=(PacketFragments&&) = default;
    auto GetQueueIt() const { return m_it; }
    bool AddFragment(NetworkBuffer data, bool is_last_frag, u16);
    bool IsFull() const;
    virtual NetworkBuffer Release() = 0;

protected:
    std::list<Hole> HoleDescriptor;
    std::list<Fragment> FragmentList {};
    size_t total_bytes_filled { 0 };
    std::list<std::pair<std::chrono::steady_clock::time_point, PacketFragmentID>>::iterator m_it;
};

class IPv4Fragments : public PacketFragments {
public:
    explicit IPv4Fragments(std::list<std::pair<std::chrono::steady_clock::time_point, PacketFragmentID>>::iterator it)
        : PacketFragments(it)
    {
    }

    ~IPv4Fragments() override
    {
        if (header) {
            free(header);
        }
    }

    void CopyInHeader(const IPv4Header&);
    NetworkBuffer Release() override;

private:
    IPv4Header* header { nullptr };
};
class IPv6Fragments : public PacketFragments {
public:
    explicit IPv6Fragments(std::list<std::pair<std::chrono::steady_clock::time_point, PacketFragmentID>>::iterator it)
        : PacketFragments(it)
    {
    }
    ~IPv6Fragments() override
    {
        if (header) {
            free(header);
        }
    }

    void CopyInHeader(const IPv6Header&, size_t);
    NetworkBuffer Release() override;

private:
    IPv6Header* header { nullptr };
    size_t header_length { };
};

struct IPv6Connection {
    EthernetConnection eth;
    IPv6Address connected_ip;
    IPv6Address our_ip;

    u32 flow_label;
    u8 traffic_class;

    NetworkBuffer BuildBufferWith(NetworkBufferConfig&, size_t) const;

    NetworkConnection ToNetworkConnection() const;
};

class NetworkDevice {
public:
    NetworkDevice(EthernetMAC mac_address,
        IPv4Address ip_str,
        u8 subnet,
        IPv4Address router,
        IPv6Address ip6,
        size_t MTU = 1500);
    ~NetworkDevice() noexcept;

    void Listen();

    void SendIPv4(NetworkBuffer data, IPv4Address, IPv4Header::ProtocolType);
    void SendIPv6(NetworkBuffer data, IPv6Address, IPv6Header::ProtocolType);
    void SendEthernet(NetworkBuffer data, EthernetMAC, u16 protocol);

    std::optional<EthernetMAC> SendArp(IPv4Address target);

    ARPBuffer MakeARPBuffer(size_t payload_size);
    IPv4Buffer MakeIPv4Buffer(size_t payload_size);

    std::optional<IPv4Connection> MakeIPConnection(IPv4Address);

    ICMPManager& GetICMPManager() { return icmpManager; };
    ICMPv6Manager& GetICMPv6Manager() { return icmpv6Manager; };
    UDPManager& GetUDPManager() { return udpManager; }
    TCPManager& GetTCPManager() { return tcpManager; }

    EthernetConnection FlipConnection(const EthernetConnection&);
    IPv4Connection FlipConnection(const IPv4Connection&);
    IPv6Connection FlipConnection(const IPv6Connection&);

    const size_t& GetMTU() const { return MTU; }
    const EthernetMAC& GetMac() const { return mac; }
    const IPv4Address& GetIPAddress() const { return ip; }
    const IPv6Address& GetIPv6Address() const { return m_ip6; }
    const IPv4Address& GetGateway() const { return m_router; }
    const SubnetMask& GetSubnetMask() const { return subnet_mask; }
    const NetworkBufferConfig& GetIPv4Config() const { return m_default_ip4_config; }
    const NetworkBufferConfig& GetIPv6Config() const { return m_default_ip6_config; }

private:
    void ResolveARP(NetworkBuffer&, EthernetConnection&);
    void ResolveIPv4(NetworkBuffer&, EthernetConnection&);
    void ResolveIPv6(NetworkBuffer&, EthernetConnection&);

    void IPTimeoutFunction(std::stop_token);

    struct IPv4Route {
        EthernetMAC dest_mac;
        IPv4Address dest_addr;
    };
    struct IPv6Route {
        EthernetMAC dest_mac;
        IPv6Address dest_addr;
    };

    std::optional<IPv4Route> MakeRoutingDecision(IPv4Address);
    std::optional<IPv6Route> MakeRoutingDecision(IPv6Address);

    int tun_fd;
    int m_thread_notify_fd;
    int m_thread_wakeup_fd;

    size_t MTU;
    IPv4Address ip;
    IPv6Address m_ip6;
    IPv4Address m_router;
    IPv6Address m_router6 {}; // FIXME: Same comment here
    SubnetMask subnet_mask;
    SubnetMask6 subnet_mask6 {}; // FIXME: This is just default initializing for now
    EthernetMAC mac;

    NetworkBufferConfig m_arp_buffer_config;
    NetworkBufferConfig m_default_ip4_config;
    NetworkBufferConfig m_default_ip6_config;
    NetworkBufferConfig m_default_l1_config;

    std::unordered_map<u32, EthernetMAC> arp_translation_table {};
    std::unordered_map<IPv4Address, std::promise<void>, IPv4Hasher> m_arp_wait_map {};

    // TODO: Make class for IPv4/6
    std::mutex m_fragment_mutex;
    std::condition_variable m_fragment_timeout_cv;
    std::unordered_map<PacketFragmentID, std::unique_ptr<PacketFragments>> m_ip_fragments;
    std::list<std::pair<std::chrono::steady_clock::time_point, PacketFragmentID>> fragment_timeout_queue {};

    std::thread listen_thread;

    static constexpr std::chrono::milliseconds fragment_timeout_time { 60000 };

    ICMPManager icmpManager;
    ICMPv6Manager icmpv6Manager;
    UDPManager udpManager;
    TCPManager tcpManager;

    std::jthread fragment_timeout;
    bool ShouldRecieveOnMac(const EthernetMAC& destination_mac) const;
};

extern std::unique_ptr<NetworkDevice> the_net_dev;