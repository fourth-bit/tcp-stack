//
// Created by Ryan Wolk on 4/10/22.
//

#include <array>
#include <cstring>

#include "NetworkDevice.h"
#include "Protocols.h"
#include "VLBuffer.h"

u16 IPv4Header::GetFlags() const
{
    return flags_and_fragment_offset & (Flags::DontFragment | Flags::MoreFragments);
}
void IPv4Header::SetFlags(u16 value)
{
    u16 host_ordered = flags_and_fragment_offset;

    // Clear the area
    host_ordered &= 0x1fff;
    // Add the new bits in
    host_ordered += value & (0xE000);

    flags_and_fragment_offset = host_ordered;
}
u16 IPv4Header::GetFragmentOffset() const
{
    return flags_and_fragment_offset & 0x1fff;
}
void IPv4Header::SetFragmentOffset(u16 value)
{
    if (value > 8191) { // 2 ** 13 - 1
        value &= ~(0b111 << 13);
    }

    u16 host_ordered = flags_and_fragment_offset;

    host_ordered &= 0b111 << 13;
    host_ordered += value;

    flags_and_fragment_offset = host_ordered;
}
u16 IPv6FragmentHeader::GetFlags() const
{
    return flags_and_fragment_offset & 1;
}
void IPv6FragmentHeader::SetFlags(u16 value)
{
    u16 host_ordered = flags_and_fragment_offset;

    // Clear the area
    host_ordered &= ~1;
    // Add the new bits in
    host_ordered += value;

    flags_and_fragment_offset = host_ordered;
}
u16 IPv6FragmentHeader::GetFragmentOffset() const
{
    return flags_and_fragment_offset >> 3;
}
void IPv6FragmentHeader::SetFragmentOffset(u16 value)
{
    if (value > 8191) { // 2 ** 13 - 1
        value &= ~(0b111 << 13);
    }

    u16 host_ordered = flags_and_fragment_offset;

    host_ordered &= 0b111;
    host_ordered += value << 3;

    flags_and_fragment_offset = host_ordered;
}

EthernetBuffer EthernetBuffer::FromVLBuffer(VLBuffer&& buffer)
{
    return EthernetBuffer(std::move(buffer));
}
EthernetHeader& EthernetBuffer::GetEthernetHeader()
{
    return m_buffer.as<EthernetHeader>();
}
VLBufferView EthernetBuffer::GetPayload()
{
    return m_buffer.AsView().SubBuffer(sizeof(EthernetHeader));
}

void EthernetBuffer::SetSourceMac(const EthernetMAC& mac)
{
    auto& eth_header = m_buffer.as<EthernetHeader>();
    std::copy(mac.begin(), mac.end(), eth_header.src_mac.begin());
}
void EthernetBuffer::SetDestMac(const EthernetMAC& mac)
{
    auto& eth_header = m_buffer.as<EthernetHeader>();
    std::copy(mac.begin(), mac.end(), eth_header.dest_mac.begin());
}
void EthernetBuffer::SetEthernetType(u16 type)
{
    auto& eth_header = m_buffer.as<EthernetHeader>();
    eth_header.ethernet_type = type;
}
void EthernetBuffer::SetupEthConnection(const EthernetConnection& connection)
{
    SetEthernetType(connection.connection_type);
    SetDestMac(connection.destination_mac);
    SetSourceMac(connection.source_mac);
}

ARPBuffer ARPBuffer::FromVLBuffer(VLBuffer&& buffer)
{
    // In the future I would like to do some form of checking
    return ARPBuffer(std::move(buffer));
}
ARPHeader& ARPBuffer::GetARPHeader()
{
    return m_buffer.AsView().SubBuffer(sizeof(EthernetHeader)).as<ARPHeader>();
}
VLBufferView ARPBuffer::GetPayload()
{
    return m_buffer.AsView().SubBuffer(sizeof(EthernetHeader) + sizeof(ARPHeader));
}

IPv4Buffer IPv4Buffer::FromVLBuffer(VLBuffer&& buf)
{
    return IPv4Buffer(std::move(buf));
}
IPv4Header& IPv4Buffer::GetIPv4Header()
{
    return m_buffer.AsView().SubBuffer(sizeof(EthernetHeader)).as<IPv4Header>();
}
VLBufferView IPv4Buffer::GetPayload()
{
    auto& header = GetIPv4Header();
    return m_buffer.AsView().SubBuffer(sizeof(EthernetHeader) + header.header_length * 4);
}

void IPv4Buffer::SetupIPConnection(const IPv4Connection& connection)
{
    SetupEthConnection(connection.eth);

    auto& header = GetIPv4Header();
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
void IPv4Buffer::CopyIPHeader(const IPv4Header& other)
{
    IPv4Header* header = &GetIPv4Header();
    // FIXME: This is problematic if I end up packing options
    memcpy(header, &other, sizeof(IPv4Header));
}
IPv4Buffer IPv4Buffer::WithSize(size_t size)
{
    return IPv4Buffer(VLBuffer::WithSize(size + sizeof(EthernetHeader) + sizeof(IPv4Header)));
}

void ARPBuffer::SetupARPHeader(arp_hardware hw_type, arp_proto pro_type)
{
    const std::unordered_map<arp_hardware, u8> hw_size_map {
        { arp_hardware::ethernet, 6 }
    };

    const std::unordered_map<arp_proto, u8> pro_size_map {
        { arp_proto::IPv4, 4 }
    };

    // Todo: Perform checks to confirm that we support the hardware and proto

    auto& arp_header = GetARPHeader();

    arp_header.hwtype = (u16)hw_type;
    arp_header.hwsize = hw_size_map.at(hw_type);

    arp_header.protype = (u16)pro_type;
    arp_header.prosize = pro_size_map.at(pro_type);
}
void ARPBuffer::SetARPOpcode(u16 opcode)
{
    auto& arp_header = GetARPHeader();
    arp_header.opcode = opcode;
}

ICMPv4Buffer ICMPv4Buffer::FromVLBuffer(VLBuffer&& buf)
{
    return ICMPv4Buffer(std::move(buf));
}
ICMPv4Header& ICMPv4Buffer::GetICMPv4Header()
{
    return IPv4Buffer::GetPayload().as<ICMPv4Header>();
}
VLBufferView ICMPv4Buffer::GetPayload()
{
    return IPv4Buffer::GetPayload().SubBuffer(sizeof(ICMPv4Header));
}
ICMPv4Buffer ICMPv4Buffer::MakeBuffer(size_t payload_size)
{
    return ICMPv4Buffer(VLBuffer::WithSize(sizeof(EthernetHeader) + sizeof(IPv4Header) + sizeof(ICMPv4Header) + payload_size));
}
u16 ICMPv4Buffer::RunICMPv4Checksum()
{
    size_t header_offset = sizeof(EthernetHeader) + GetIPv4Header().header_length * 4;
    size_t header_len = m_buffer.Size() - header_offset;

    return IPv4Checksum(m_buffer.Data() + header_offset, header_len);
}
void ICMPv4Buffer::ApplyICMPv4Checksum()
{
    GetICMPv4Header().checksum = RunICMPv4Checksum();
}
