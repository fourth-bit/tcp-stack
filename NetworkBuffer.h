//
// Created by Ryan Wolk on 6/6/22.
//

#pragma once

#include <list>
#include <memory>
#include <optional>
#include <unordered_map>

#include "Badge.h"
#include "IPv4Address.h"
#include "Protocols.h"
#include "VLBuffer.h"

enum class LayerType {
    Ethernet,
    ARP,
    IPv4,
    IPv6,
    ICMP,
    ICMPv6,
    TCP,
    UDP,
    Unknown,
};

class NetworkBuffer;
struct IPv6Connection;

class NetworkLayer {
    friend class NetworkBuffer;

public:
    virtual ~NetworkLayer() = default;

    struct Config {
        virtual ~Config() = default;

        virtual size_t LayerSize() = 0;
        virtual void ConfigureLayer(NetworkLayer&) = 0;
    };

    template <typename T>
    T& As() { return reinterpret_cast<T&>(*this); }
    size_t Size() { return m_view.Size(); }
    size_t UpperLayerPayload();
    u8* Data() { return m_view.Data(); }

protected:
    VLBufferView m_view;
    NetworkBuffer* m_parent;

private:
    NetworkLayer(VLBufferView view, NetworkBuffer* parent)
        : m_view(view)
    {
        m_parent = parent;
    }
};

class EthernetLayer : public NetworkLayer {
public:
    struct Config : NetworkLayer::Config {
        EthernetMAC src_addr;
        EthernetMAC dest_addr;
        u16 connection_type;

        constexpr size_t LayerSize() override { return sizeof(EthernetHeader); }
        void ConfigureLayer(NetworkLayer&) override;
    };

    void SetupEthConnection(const EthernetConnection&);
    void SetSourceMac(const EthernetMAC& mac);
    void SetDestMac(const EthernetMAC& mac);
    void SetEthernetType(u16 type);

    EthernetHeader& GetHeader();
};
class ARPLayer : public NetworkLayer {
public:
    struct Config : NetworkLayer::Config {
        std::optional<arp_hardware> hw_type;
        std::optional<arp_proto> pro_type;

        constexpr size_t LayerSize() override { return sizeof(ARPHeader); }
        void ConfigureLayer(NetworkLayer&) override;
    };

    void SetupARPHeader(arp_hardware, arp_proto);
    void SetARPOpcode(u16 opcode);

    ARPHeader& GetHeader();

    inline static const std::unordered_map<arp_hardware, u8> hw_size_map {
        { arp_hardware::ethernet, 6 }
    };

    inline static const std::unordered_map<arp_proto, u8> pro_size_map {
        { arp_proto::IPv4, 4 }
    };
};
class IPv4Layer : public NetworkLayer {
public:
    struct Config : NetworkLayer::Config {
        IPv4Address src_ip {};
        IPv4Address dest_ip {};

        u8 flags { 0 };
        u8 tos { 0 };
        u8 ttl { 64 };
        u8 proto { 0 };

        size_t LayerSize() override
        { /* Fixme: As we add the possibility to have options change this  */
            return 20;
        }
        void ConfigureLayer(NetworkLayer&) override;
    };

    struct __attribute__((packed)) PsuedoHeader {
        IPv4Address source;
        IPv4Address dest;
        u8 zero { 0 };
        u8 protocol;
        NetworkOrdered<u16> length;
    };

    IPv4Header& GetHeader();

    u16 RunChecksum();
    void ApplyChecksum();

    PsuedoHeader BuildPsuedoHeader();

    void SetupConnection(const IPv4Connection&);
    void CopyHeader(const IPv4Header&);
    void SetDestIP(const IPv4Address&);
    void SetSourceIP(const IPv4Address&);
    void SetLength(u16);
    void SetFlags(IPv4Header::Flags flags);
    void SetFragmentOffset(u16 flags);
    void SetID(u16 id);
};
class IPv6Layer : public NetworkLayer {
public:
    struct Config : NetworkLayer::Config {
        IPv6Address src_ip {};
        IPv6Address dest_ip {};

        u32 flow_label { 0 };
        u8 traffic_class { 0 };
        u8 hop_limit { 255 };

        size_t LayerSize() override { return sizeof(IPv6Header);}
        void ConfigureLayer(NetworkLayer&) override;
    };

    struct __attribute__((packed)) PsuedoHeader {
        NetworkIPv6Address source;
        NetworkIPv6Address dest;
        NetworkOrdered<u32> length;
        u16 zero1 { 0 };
        u8 zero2 { 0 };
        u8 next_header;
    };

    IPv6Header& GetHeader();
    PsuedoHeader BuildPseudoHeader(u8 next_header);

    void SetupConnection(const IPv6Connection&);
    void SetSourceAddr(NetworkIPv6Address);
    void SetDestAddr(NetworkIPv6Address);
    void SetProtocol(IPv6Header::ProtocolType);
    IPv6Address GetSourceAddr();
    IPv6Address GetDestAddr();

    u32 GetVersion();
    u32 GetTrafficClass();
    u32 GetFlowLabel();
    void SetVersion(u32);
    void SetTrafficClass(u32);
    void SetFlowLabel(u32);
};
class ICMPLayer : public NetworkLayer {
public:
    struct Config : NetworkLayer::Config {
        constexpr size_t LayerSize() override { return sizeof(ICMPv4Header); }
        void ConfigureLayer(NetworkLayer&) override;
    };
    ICMPv4Header& GetHeader();

    void ApplyICMPv4Checksum(u64 payload_length);
    u16 RunICMPv4Checksum(u64 payload_length);
};
class ICMPv6Layer : public NetworkLayer {
public:
    struct Config : NetworkLayer::Config {
        constexpr size_t LayerSize() override { return sizeof(ICMPv6Header); }
        void ConfigureLayer(NetworkLayer&) override;
    };
    ICMPv6Header& GetHeader();

    void ApplyICMPv6Checksum();
    u16 RunICMPv6Checksum();

    void SetType(u16);
    void SetCode(u16);
    u16 GetType();
    u16 GetCode();
};
class UDPLayer : public NetworkLayer {
public:
    struct Config : NetworkLayer::Config {
        u16 source_port;
        u16 dest_port;

        constexpr size_t LayerSize() override { return sizeof(UDPHeader); }
        void ConfigureLayer(NetworkLayer&) override;
    };

    UDPHeader& GetHeader();

    void SetSourcePort(u16);
    void SetDestPort(u16);
    void SetLength(u16);

    u16 RunChecksum();
    void ApplyChecksum();
    u16 RunChecksum(IPv4Layer::PsuedoHeader);
    void ApplyChecksum(IPv4Layer::PsuedoHeader);
};
class TCPLayer : public NetworkLayer {
public:
    struct Config : NetworkLayer::Config {
        u16 source_port;
        u16 dest_port;

        std::optional<u16> MSS_option;

        // Returns options length IN BYTES
        size_t options_length();

        size_t LayerSize() override { return sizeof(TCPHeader) + options_length(); };

        void ConfigureLayer(NetworkLayer&) override;
    };

    TCPHeader& GetHeader();
    size_t GetHeaderSize();
    void SetSourcePort(u16);
    void SetDestPort(u16);
    void SetAckNum(u32);
    void SetSeqNum(u32);
    void SetFlags(u16);
    void SetWindow(u16);

    u16 RunChecksum();
    void ApplyChecksum();
    u16 RunChecksum(IPv4Layer::PsuedoHeader);
    void ApplyChecksum(IPv4Layer::PsuedoHeader);
};

template <LayerType T>
struct LayerTypeToClass {
};
template <>
struct LayerTypeToClass<LayerType::Ethernet> {
    using type = EthernetLayer;
};
template <>
struct LayerTypeToClass<LayerType::ARP> {
    using type = ARPLayer;
};
template <>
struct LayerTypeToClass<LayerType::IPv4> {
    using type = IPv4Layer;
};
template <>
struct LayerTypeToClass<LayerType::ICMP> {
    using type = ICMPLayer;
};
template <>
struct LayerTypeToClass<LayerType::ICMPv6> {
    using type = ICMPv6Layer;
};
template <>
struct LayerTypeToClass<LayerType::IPv6> {
    using type = IPv6Layer;
};
template <>
struct LayerTypeToClass<LayerType::TCP> {
    using type = TCPLayer;
};
template <>
struct LayerTypeToClass<LayerType::UDP> {
    using type = UDPLayer;
};

class NetworkBufferConfig {
public:
    template <LayerType T>
    void AddLayer(typename LayerTypeToClass<T>::type::Config const& config)
    {
        using CfgType = typename LayerTypeToClass<T>::type::Config;

        // Fixme: this is a crime against coding. Use a copy constructor
        std::unique_ptr config_heap = std::unique_ptr<CfgType>(new CfgType);
        std::copy(&config, &config + 1, config_heap.get());

        m_layer_configs.emplace_back(T, std::move(config_heap));
    }

    template <LayerType T>
    void AddLayer()
    {
        AddLayer<T>(typename LayerTypeToClass<T>::type::Config {});
    }

    template <LayerType T>
    typename LayerTypeToClass<T>::type::Config* LayerAsRef()
    {
        for (auto const& [type, config] : m_layer_configs) {
            if (type == T) {
                return reinterpret_cast<typename LayerTypeToClass<T>::type::Config*>(config.get());
            }
        }

        return nullptr;
    }

    template <LayerType T>
    bool HasLayer() const
    {
        for (auto const& [type, config] : m_layer_configs) {
            if (type == T) {
                return true;
            }
        }
        return false;
    }

    size_t HeaderSize() const
    {
        size_t size = 0;
        for (auto const& [_, config] : m_layer_configs) {
            size += config->LayerSize();
        }

        return size;
    }

    NetworkBuffer BuildBuffer(size_t payload_size) const;

private:
    std::list<std::pair<LayerType, std::unique_ptr<NetworkLayer::Config>>> m_layer_configs;
};

class NetworkBuffer {
public:
    explicit NetworkBuffer(VLBuffer&&);
    NetworkBuffer(NetworkBuffer&) = delete;
    //    NetworkBuffer(NetworkBuffer&& other)
    //        : m_buffer(std::move(other.m_buffer))
    //        , m_length(other.m_length)
    //        , m_layers(std::move(other.m_layers))
    //    {
    //    }
    NetworkBuffer(NetworkBuffer&&) = default;

    NetworkBuffer& operator=(NetworkBuffer&&) = default;

    static NetworkBuffer WithSize(size_t length) { return NetworkBuffer(VLBuffer::WithSize(length)); }

    NetworkBuffer Copy();
    void CopyLayout(NetworkBuffer const& other);
    NetworkLayer& AddLayer(size_t, LayerType);
    template <LayerType T>
    typename LayerTypeToClass<T>::type& AddLayer(size_t length)
    {
        using LayerT = typename LayerTypeToClass<T>::type;

        m_layers.emplace_back(T, std::unique_ptr<NetworkLayer>(new NetworkLayer(m_buffer.AsView().SubBuffer(m_length), this)));
        auto& layer = m_layers.back();
        layer.second->m_view = layer.second->m_view.ShrinkEnd(length);

        m_length += length;

        return reinterpret_cast<LayerT&>(*layer.second);
    }

    void ResetLayers()
    {
        m_layers.erase(m_layers.begin(), m_layers.end());
        m_length = 0;
    }

    void RemoveLayersAbove(NetworkLayer*);

    NetworkLayer* GetLayer(LayerType);
    template <LayerType T>
    typename LayerTypeToClass<T>::type* GetLayer()
    {
        for (auto& [list_type, layer] : m_layers) {
            if (list_type == T) {
                return reinterpret_cast<typename LayerTypeToClass<T>::type*>(layer.get());
            }
        }

        return nullptr;
    }

    void Hexdump() { m_buffer.Hexdump(); }

    void ResizeTop(size_t);
    [[deprecated("Instead change to using Network Buffer everywhere")]] VLBuffer&& Release() { return std::move(m_buffer); };
    VLBufferView GetPayload();
    template <typename T>
    T& GetPayload() { return GetPayload().as<T>(); }
    size_t Size()
    { /* m_length does not account for payload size */
        return m_buffer.Size();
    }
    u8* Data() { return m_buffer.Data(); }

    auto begin() { return m_layers.begin(); }
    auto end() { return m_layers.end(); }

private:
    VLBuffer m_buffer;
    std::list<std::pair<LayerType, std::unique_ptr<NetworkLayer>>> m_layers;
    size_t m_length { 0 };
};
