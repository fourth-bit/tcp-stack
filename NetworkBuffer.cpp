//
// Created by Ryan Wolk on 6/6/22.
//

#include "NetworkBuffer.h"
#include "NetworkDevice.h"
#include <cstring>
#include <cassert>
#include <iostream>
#include <netinet/ip.h>
#include <unordered_map>

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
    // FIXME: This is problematic if I end up packing options
    memcpy(header, &other, sizeof(IPv4Header));
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

void EthernetLayer::Config::ConfigureLayer(NetworkLayer& net_layer)
{
    auto& eth_layer = net_layer.As<EthernetLayer>();
    eth_layer.SetSourceMac(src_addr);
    eth_layer.SetDestMac(dest_addr);
    eth_layer.SetEthernetType(connection_type);
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

static u16 GenerateIPID() {
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
void ICMPLayer::Config::ConfigureLayer(NetworkLayer&)
{
}

void UDPLayer::Config::ConfigureLayer(NetworkLayer& net_layer)
{
    auto& udp = net_layer.As<UDPLayer>();
    udp.SetDestPort(dest_port);
    udp.SetSourcePort(source_port);
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
