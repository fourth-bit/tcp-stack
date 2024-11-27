//
// Created by Ryan Wolk on 6/6/22.
//

#include "NetworkBuffer.h"
#include "NetworkDevice.h"
#include <cassert>
#include <cstring>
#include <iostream>
#include <netinet/ip.h>
#include <unordered_map>

size_t NetworkLayer::UpperLayerPayload()
{
    size_t size = m_parent->Size();

    for (auto& [_, layer] : *m_parent) {
        if (layer.get() == this) {
            size -= Size();
            break;
        }

        size -= layer->Size();
    }

    return size;
}
void EthernetLayer::SetupEthConnection(const EthernetConnection& connection)
{
    SetEthernetType(connection.connection_type);
    SetDestMac(connection.destination_mac);
    SetSourceMac(connection.source_mac);
}
void EthernetLayer::SetSourceMac(const EthernetMAC& mac)
{
    auto& eth_header = GetHeader();
    std::copy(mac.begin(), mac.end(), eth_header.src_mac.begin());
}
void EthernetLayer::SetDestMac(const EthernetMAC& mac)
{
    auto& eth_header = GetHeader();
    std::copy(mac.begin(), mac.end(), eth_header.dest_mac.begin());
}
void EthernetLayer::SetEthernetType(u16 type)
{
    auto& eth_header = GetHeader();
    eth_header.ethernet_type = type;
}
EthernetHeader& EthernetLayer::GetHeader()
{
    return m_view.as<EthernetHeader>();
}

void ARPLayer::SetupARPHeader(arp_hardware hw_type, arp_proto pro_type)
{
    // Todo: Perform checks to confirm that we support the hardware and proto

    auto& arp_header = GetHeader();

    arp_header.hwtype = (u16)hw_type;
    arp_header.hwsize = hw_size_map.at(hw_type);

    arp_header.protype = (u16)pro_type;
    arp_header.prosize = pro_size_map.at(pro_type);
}
void ARPLayer::SetARPOpcode(u16 opcode)
{
    auto& arp_header = GetHeader();
    arp_header.opcode = opcode;
}
ARPHeader& ARPLayer::GetHeader()
{
    return m_view.as<ARPHeader>();
}

IPv4Header& IPv4Layer::GetHeader()
{
    return m_view.as<IPv4Header>();
}
u16 IPv4Layer::RunChecksum()
{
    return IPv4Checksum(&GetHeader(), GetHeader().header_length * 4);
}
void IPv4Layer::SetupConnection(const IPv4Connection& connection)
{
    auto& header = GetHeader();
    header.version = 4;
    header.source_ip = connection.our_ip.GetAddress();
    header.dest_ip = connection.connected_ip.GetAddress();
    header.time_to_live = 64;
    header.header_length = 5;
    header.id = connection.id;
    header.type_of_service = connection.type_of_service;

    header.SetFlags(0);
    header.SetFragmentOffset(0);
}
void IPv4Layer::CopyHeader(const IPv4Header& other)
{
    IPv4Header* header = &GetHeader();
    memcpy(header, &other, other.header_length * 4);
}
void IPv4Layer::ApplyChecksum()
{
    IPv4Header& header = GetHeader();
    header.header_checksum = 0;
    header.header_checksum = RunChecksum();
}
void IPv4Layer::SetDestIP(const IPv4Address& address)
{
    GetHeader().source_ip = address.GetAddress();
}
void IPv4Layer::SetSourceIP(const IPv4Address& address)
{
    GetHeader().dest_ip = address.GetAddress();
}
void IPv4Layer::SetLength(u16 length)
{
    GetHeader().total_length = length;
}
IPv4Layer::PsuedoHeader IPv4Layer::BuildPsuedoHeader()
{
    auto& header = GetHeader();
    return IPv4Layer::PsuedoHeader {
        .source = IPv4Address(header.source_ip),
        .dest = IPv4Address(header.dest_ip),
        .zero = 0,
        .protocol = header.protocol,
        .length = NetworkOrdered<u16>((u16)header.total_length - header.header_length * 4),
    };
}
void IPv4Layer::SetFlags(IPv4Header::Flags flags)
{
    auto& header = GetHeader();
    header.SetFlags(flags);
}
void IPv4Layer::SetFragmentOffset(u16 offset)
{
    auto& header = GetHeader();
    header.SetFragmentOffset(offset);
}
void IPv4Layer::SetID(u16 id)
{
    GetHeader().id = id;
}
ICMPv4Header& ICMPLayer::GetHeader()
{
    return m_view.as<ICMPv4Header>();
}
void ICMPLayer::ApplyICMPv4Checksum(u64 payload_length)
{
    GetHeader().checksum = 0;
    GetHeader().checksum = RunICMPv4Checksum(payload_length);
}
u16 ICMPLayer::RunICMPv4Checksum(u64 payload_length)
{
    return IPv4Checksum(m_view.Data(), m_view.Size() + payload_length);
}

NetworkBuffer::NetworkBuffer(VLBuffer&& buffer)
    : m_buffer(std::move(buffer))
    , m_layers()
{
}

NetworkLayer& NetworkBuffer::AddLayer(size_t length, LayerType type)
{
    m_layers.emplace_back(type, std::unique_ptr<NetworkLayer>(new NetworkLayer(m_buffer.AsView().SubBuffer(m_length), this)));
    auto& layer = m_layers.back();
    layer.second->m_view = layer.second->m_view.ShrinkEnd(length);

    m_length += length;

    return *layer.second;
}
NetworkLayer* NetworkBuffer::GetLayer(LayerType type)
{
    for (auto& [list_type, layer] : m_layers) {
        if (list_type == type) {
            return layer.get();
        }
    }

    return nullptr;
}
void NetworkBuffer::ResizeTop(size_t length)
{
    auto& top_layer_pair = m_layers.back();
    auto* top_layer = top_layer_pair.second.get();

    m_length -= top_layer->Size();

    *top_layer = NetworkLayer(m_buffer.AsView().SubBuffer(m_length), this);

    top_layer->m_view = top_layer->m_view.ShrinkEnd(length);

    m_length += length;
}

VLBufferView NetworkBuffer::GetPayload()
{
    return m_buffer.AsView().SubBuffer(m_length);
}

NetworkBuffer NetworkBufferConfig::BuildBuffer(size_t payload_size) const
{
    size_t buffer_len = 0;
    for (auto& [_, ptr] : m_layer_configs) {
        buffer_len += ptr->LayerSize();
    }

    auto buffer = NetworkBuffer::WithSize(buffer_len + payload_size);
    for (auto& [type, ptr] : m_layer_configs) {
        auto& layer = buffer.AddLayer(ptr->LayerSize(), type);
        ptr->ConfigureLayer(layer);
    }

    return buffer;
}
void NetworkBufferConfig::AddLayer(LayerType type, std::unique_ptr<NetworkLayer::Config> config)
{
    m_layer_configs.emplace_back(type, std::move(config));
}
NetworkBufferConfig NetworkBufferConfig::Copy() const
{
    NetworkBufferConfig new_config { };

    for (auto& [type, config_ptr] : m_layer_configs) {
        new_config.AddLayer(type, std::unique_ptr<NetworkLayer::Config>(config_ptr->Copy()));
    }

    return new_config;
}

void EthernetLayer::Config::ConfigureLayer(NetworkLayer& net_layer)
{
    auto& eth_layer = net_layer.As<EthernetLayer>();
    eth_layer.SetSourceMac(src_addr);
    eth_layer.SetDestMac(dest_addr);
    eth_layer.SetEthernetType(connection_type);
}
NetworkLayer::Config* EthernetLayer::Config::Copy() const
{
    return new EthernetLayer::Config(*this);
}

void ARPLayer::Config::ConfigureLayer(NetworkLayer& net_layer)
{
    auto& arp_hdr = net_layer.As<ARPLayer>().GetHeader();
    if (hw_type) {
        arp_hdr.hwtype = (u16)(*hw_type);
        arp_hdr.hwsize = hw_size_map.at(*hw_type);
    }
    if (pro_type) {
        arp_hdr.protype = (u16)(*pro_type);
        arp_hdr.prosize = pro_size_map.at(*pro_type);
    }
}
NetworkLayer::Config* ARPLayer::Config::Copy() const
{
    return new ARPLayer::Config(*this);
}

static u16 GenerateIPID()
{
    return rand();
}

void IPv4Layer::Config::ConfigureLayer(NetworkLayer& net_layer)
{
    auto& ip = net_layer.As<IPv4Layer>();
    auto& header = ip.GetHeader();
    header.version = 4;
    header.source_ip = src_ip.GetAddress();
    header.dest_ip = dest_ip.GetAddress();
    header.time_to_live = ttl;
    header.header_length = LayerSize() / 4;
    header.id = GenerateIPID();
    header.type_of_service = tos;
    header.protocol = proto;

    header.SetFlags(flags);
    header.SetFragmentOffset(0);
}
NetworkLayer::Config* IPv4Layer::Config::Copy() const
{
    return new IPv4Layer::Config(*this);
}
void ICMPLayer::Config::ConfigureLayer(NetworkLayer&)
{
}
NetworkLayer::Config* ICMPLayer::Config::Copy() const
{
    return new ICMPLayer::Config();
}
IPv6Header& IPv6Layer::GetHeader() {
    return m_view.as<IPv6Header>();
}
void IPv6Layer::Config::ConfigureLayer(NetworkLayer& layer)
{
    auto& ipv6 = layer.As<IPv6Layer>();
    auto& header = ipv6.GetHeader();
    ipv6.SetVersion(6);
    header.source_ip = (NetworkIPv6Address)src_ip;
    header.dest_ip = (NetworkIPv6Address)dest_ip;
    ipv6.SetFlowLabel(flow_label);
    ipv6.SetTrafficClass(traffic_class);
    header.hop_limit = hop_limit;
    header.payload_length = layer.UpperLayerPayload();
    header.next_header = protocol;
}
NetworkLayer::Config* IPv6Layer::Config::Copy() const
{
    return new IPv6Layer::Config(*this);
}
void IPv6Layer::SetupConnection(const IPv6Connection& connection)
{
    auto& header = GetHeader();
    SetVersion(6);
    header.source_ip = (NetworkIPv6Address)connection.our_ip;
    header.dest_ip = (NetworkIPv6Address)connection.connected_ip;
    SetFlowLabel(connection.flow_label);
    SetTrafficClass(connection.traffic_class);
    header.hop_limit = 255;
    header.payload_length = UpperLayerPayload();
}
IPv6Layer::PsuedoHeader IPv6Layer::BuildPseudoHeader()
{
    auto& header = GetHeader();
    return IPv6Layer::PsuedoHeader {
        .source = header.source_ip,
        .dest = header.dest_ip,
        .length = NetworkOrdered<u32>(header.payload_length),
        .zero1 = 0,
        .zero2 = 0,
        .next_header = header.next_header,
    };
}
void IPv6Layer::SetSourceAddr(NetworkIPv6Address address)
{
    auto& header = GetHeader();
    header.source_ip = address;
}
void IPv6Layer::SetDestAddr(NetworkIPv6Address address)
{
    auto& header = GetHeader();
    header.dest_ip = address;
}
void IPv6Layer::SetProtocol(IPv6Header::ProtocolType protocol)
{
    // TODO: When we add options (e.g. Fragmentation), this needs to be smarter
    auto& header = GetHeader();
    header.next_header = protocol;
}
IPv6Address IPv6Layer::GetDestAddr()
{
    auto& header = GetHeader();
    return (IPv6Address)header.dest_ip;
}
IPv6Address IPv6Layer::GetSourceAddr()
{
    auto& header = GetHeader();
    return (IPv6Address)header.source_ip;
}
u32 IPv6Layer::GetVersion()
{
    auto& header = GetHeader();
    return header.first_32_bits.Convert() >> 28;
}
u32 IPv6Layer::GetTrafficClass()
{
    auto& header = GetHeader();
    return (header.first_32_bits.Convert() >> 20) & 0xff;
}
u32 IPv6Layer::GetFlowLabel()
{
    auto& header = GetHeader();
    return header.first_32_bits & 0xf'ffff;
}
void IPv6Layer::SetVersion(u32 version)
{
    auto& header = GetHeader();
    u32 bits = header.first_32_bits.Convert();
    bits &= 0xfff'ffff;
    bits |= version << 28;
    header.first_32_bits = bits;
}
void IPv6Layer::SetTrafficClass(u32 traffic_class)
{
    auto& header = GetHeader();
    u32 bits = header.first_32_bits.Convert();
    bits &= 0xf00f'ffff;
    bits |= traffic_class << 20;
    header.first_32_bits = bits;
}
void IPv6Layer::SetFlowLabel(u32 flow_label)
{
    auto& header = GetHeader();
    u32 bits = header.first_32_bits.Convert();
    bits &= 0xfff0'0000;
    bits |= flow_label;
    header.first_32_bits = bits;
}
ICMPv6Header& ICMPv6Layer::GetHeader()
{
    return m_view.as<ICMPv6Header>();
}
void ICMPv6Layer::ApplyICMPv6Checksum()
{
    ICMPv6Header& header = GetHeader();
    header.checksum = 0;
    header.checksum = RunICMPv6Checksum();
}
u16 ICMPv6Layer::RunICMPv6Checksum()
{
    // We need to calculate a pseudo-header for ipv6
    IPv6Layer* ip6 = m_parent->GetLayer<LayerType::IPv6>();
    auto& header = GetHeader();
    auto pheader = ip6->BuildPseudoHeader();

    u32 csum = IPv4ChecksumAdd(&pheader, sizeof(pheader));
    u8* data = m_view.Data();
    csum = IPv4ChecksumAdd(data, pheader.length, csum);

    return IPv4ChecksumEnd(csum);
}
void ICMPv6Layer::SetType(u16 type)
{
    ICMPv6Header& header = GetHeader();
    header.type = type;
}
void ICMPv6Layer::SetCode(u16 code)
{
    ICMPv6Header& header = GetHeader();
    header.code = code;
}
u16 ICMPv6Layer::GetType()
{
    ICMPv6Header& header = GetHeader();
    return header.type;
}
u16 ICMPv6Layer::GetCode()
{
    ICMPv6Header& header = GetHeader();
    return header.code;
}
void ICMPv6Layer::Config::ConfigureLayer(NetworkLayer&)
{
}
NetworkLayer::Config* ICMPv6Layer::Config::Copy() const
{
    return new ICMPv6Layer::Config();
}

void UDPLayer::Config::ConfigureLayer(NetworkLayer& net_layer)
{
    auto& udp = net_layer.As<UDPLayer>();
    udp.SetDestPort(dest_port);
    udp.SetSourcePort(source_port);
}
NetworkLayer::Config* UDPLayer::Config::Copy() const
{
    return new UDPLayer::Config(*this);
}
UDPHeader& UDPLayer::GetHeader()
{
    return m_view.as<UDPHeader>();
}
void UDPLayer::SetSourcePort(u16 port)
{
    GetHeader().source_port = port;
}
void UDPLayer::SetDestPort(u16 port)
{
    GetHeader().dest_port = port;
}
void UDPLayer::SetLength(u16 length)
{
    GetHeader().length = length;
}

u16 UDPLayer::RunChecksum()
{
    // FIXME: make IPv4/6 generic
    IPv4Layer* ip_layer = m_parent->GetLayer<LayerType::IPv4>();

    auto pheader = ip_layer->BuildPsuedoHeader();
    u32 csum = IPv4ChecksumAdd(&pheader, sizeof(pheader));
    auto& header = GetHeader();
    u8* data = m_view.Data();
    csum = IPv4ChecksumAdd(data, header.length, csum);

    return IPv4ChecksumEnd(csum);
}
void UDPLayer::ApplyChecksum()
{
    UDPHeader& header = GetHeader();
    header.checksum = 0;
    header.checksum = RunChecksum();
}
u16 UDPLayer::RunChecksum(IPv4Layer::PsuedoHeader pheader)
{
    u32 csum = IPv4ChecksumAdd(&pheader, sizeof(pheader));
    auto& header = GetHeader();
    u8* data = m_view.Data();
    csum = IPv4ChecksumAdd(data, header.length, csum);

    return IPv4ChecksumEnd(csum);
}
void UDPLayer::ApplyChecksum(IPv4Layer::PsuedoHeader pheader)
{
    UDPHeader& header = GetHeader();
    header.checksum = 0;
    header.checksum = RunChecksum(pheader);
}
TCPHeader& TCPLayer::GetHeader()
{
    return m_view.as<TCPHeader>();
}
size_t TCPLayer::GetHeaderSize()
{
    auto& header = GetHeader();
    return header.header_length * 4;
}
void TCPLayer::Config::ConfigureLayer(NetworkLayer& layer)
{
    auto& tcp = layer.As<TCPLayer>();
    auto& header = tcp.GetHeader();

    header.source_port = source_port;
    header.dest_port = dest_port;
    header.window_size = 0;
    header.urgent_pointer = 0;
    header.flags = 0;
    header.checksum = 0;
    header.header_length = 5 + options_length() / 4;
    header.seq_num = 0;
    header.ack_num = 0;

    size_t options_offset = 0;
    if (MSS_option.has_value()) {
        header.options[options_offset + 0] = 2;
        header.options[options_offset + 1] = 4;

        NetworkOrdered nw_mss = MSS_option.value();
        *(u16*)(header.options + options_offset + 2) = nw_mss.WithNetworkOrder();

        options_offset += 4;
    }

    if (options_offset % 4 != 0) {
        // Add an end of options list option
        header.options[options_offset] = 0;
    }
}
size_t TCPLayer::Config::options_length()
{
    size_t options_size = 0;
    if (MSS_option.has_value()) {
        options_size += 4;
    }

    if (options_size % 4 != 0) {
        options_size += 4 - options_size % 4;
    }

    return options_size;
}
NetworkLayer::Config* TCPLayer::Config::Copy() const
{
    return new TCPLayer::Config(*this);
}

void TCPLayer::SetSourcePort(u16 port)
{
    auto& header = GetHeader();
    header.source_port = port;
}
void TCPLayer::SetDestPort(u16 port)
{
    auto& header = GetHeader();
    header.dest_port = port;
}
void TCPLayer::SetAckNum(u32 num)
{
    auto& header = GetHeader();
    header.ack_num = num;
}
void TCPLayer::SetSeqNum(u32 num)
{
    auto& header = GetHeader();
    header.seq_num = num;
}
void TCPLayer::SetFlags(u16 flags)
{
    auto& header = GetHeader();
    header.flags = flags;
}
void TCPLayer::SetWindow(u16 size)
{
    auto& header = GetHeader();
    header.window_size = size;
}
u16 TCPLayer::RunChecksum()
{
    // Fixme: Change (with UDP) to be IPv4/6 Generic
    IPv4Layer* ip_layer = m_parent->GetLayer<LayerType::IPv4>();

    auto pheader = ip_layer->BuildPsuedoHeader();
    u32 csum = IPv4ChecksumAdd(&pheader, sizeof(pheader));

    csum = IPv4ChecksumAdd(m_view.Data(), pheader.length, csum);

    return IPv4ChecksumEnd(csum);
}
void TCPLayer::ApplyChecksum()
{
    auto& header = GetHeader();
    header.checksum = 0;
    header.checksum = RunChecksum();
}
u16 TCPLayer::RunChecksum(IPv4Layer::PsuedoHeader pheader)
{
    u32 csum = IPv4ChecksumAdd(&pheader, sizeof(pheader));
    u8* data = m_view.Data();
    csum = IPv4ChecksumAdd(data, pheader.length, csum);

    return IPv4ChecksumEnd(csum);
}
void TCPLayer::ApplyChecksum(IPv4Layer::PsuedoHeader pheader)
{
    TCPHeader& header = GetHeader();
    header.checksum = 0;
    header.checksum = RunChecksum(pheader);
}
NetworkBuffer NetworkBuffer::Copy()
{
    NetworkBuffer buffer = NetworkBuffer(m_buffer.Copy());
    for (auto& [layer_type, layer] : m_layers) {
        buffer.AddLayer(layer->Size(), layer_type);
    }

    return buffer;
}
void NetworkBuffer::CopyLayout(const NetworkBuffer& other)
{
    ResetLayers();
    for (auto& [layer_type, layer] : other.m_layers) {
        AddLayer(layer->Size(), layer_type);
    }
}

void NetworkBuffer::RemoveLayersAbove(NetworkLayer* layer)
{
    decltype(m_layers)::iterator one_past_layer_it;

    for (auto it = m_layers.begin(); it != m_layers.end(); ++it) {
        if (it->second.get() == layer) {
            ++it;
            one_past_layer_it = it;
            break;
        }
    }

    u64 extra_length = 0;
    for (auto it = one_past_layer_it; it != m_layers.end(); ++it) {
        extra_length += it->second->Size();
    }
    m_length -= extra_length;

    m_layers.erase(one_past_layer_it, m_layers.end());
}
