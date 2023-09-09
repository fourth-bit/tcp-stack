//
// Created by Ryan Wolk on 3/25/22.
//

#pragma once

#include "NetworkOrder.h"
#include "VLBuffer.h"
#include "EthernetMAC.h"
#include "IntDefs.h"

struct EthernetConnection;
struct IPv4Connection;

struct EthernetHeader {
    // Destination mac address
    EthernetMAC dest_mac;
    // Source mac address
    EthernetMAC src_mac;
    // This field contains the type of payload (IPv4, IPv6, ARP)
    NetworkOrdered<u16> ethernet_type;
} __attribute__((packed));

// Header for the address resolution protocol
struct ARPHeader {
    // This is the link layer type (ethernet, wifi)
    NetworkOrdered<u16> hwtype;
    // This is the protocol type (IPv4)
    NetworkOrdered<u16> protype;
    // This is like mac address size
    u8 hwsize;
    // This is like IP address size
    u8 prosize;
    // Request or Reply
    NetworkOrdered<u16> opcode;
} __attribute__((packed));

enum class arp_hardware : u16 {
    ethernet = 0x0001,
};

enum class arp_proto : u16 {
    IPv4 = 0x0800,
};

struct ARP_IPv4 {
    u8 src_mac[6];
    NetworkOrdered<u32> src_ip;
    u8 dest_mac[6];
    NetworkOrdered<u32> dest_ip;
} __attribute__((packed));

struct IPv4Header {
    enum ProtocolType {
        ICMP = 1,
        TCP = 6,
        UDP = 17,
    };
    enum Flags {
        DontFragment = 0x4000,
        MoreFragments = 0x2000,
        NoFlags = 0x0000,
    };

    // Length of the header in 32-bit words. Always >= 5
    u8 header_length : 4;
    // IP version (always 4)
    u8 version : 4;
    // From the first ip version. Tells about quality of service
    u8 type_of_service;
    // Length of the entire packet (bytes)
    NetworkOrdered<u16> total_length;
    // Used in packet fragmentation. Is the fragment number
    NetworkOrdered<u16> id;
    // Control flags. Is fragmentation allowed? Last Fragment?
    //      And Where is the fragment in the entire message
    NetworkOrdered<u16> flags_and_fragment_offset;
    // This field is decrement every hop a packet take. When it reaches 0, the
    // packet is dropped
    u8 time_to_live;
    // What is the format of the payload: (e.g TCP, UDP, ICMP)
    u8 protocol;
    // Verifies integrity
    NetworkOrdered<u16> header_checksum;
    NetworkOrdered<u32> source_ip;
    NetworkOrdered<u32> dest_ip;
    u8 options[];

    u16 GetFlags() const;
    void SetFlags(u16);

    u16 GetFragmentOffset() const;
    void SetFragmentOffset(u16);

    bool IsFragment() const { return (GetFlags() & MoreFragments) || GetFragmentOffset() != 0; }
} __attribute__((packed));

struct ICMPv4Header {
    enum RequestType {
        EchoResp = 0,
        DestUnreachable = 3,
        EchoReq = 8,
    };

    // Purpose of the message (e.g. Echo Request)
    u8 type;
    // Meaning of the message like destination unreachable
    u8 code;
    // Uses the IP checksum to verify the header
    // Payload in included in the calculation of the checksum
    NetworkOrdered<u16> checksum;
} __attribute__((packed));

struct ICMPv4Echo {
    // Sender sets this to know what process is meant to receive it
    NetworkOrdered<u16> id;
    // The ping number
    NetworkOrdered<u16> seq;
    // Optional field. Can contain time information
    u8 data[];
} __attribute__((packed));

struct UDPHeader {
    NetworkOrdered<u16> source_port;
    NetworkOrdered<u16> dest_port;

    NetworkOrdered<u16> length;
    NetworkOrdered<u16> checksum;
} __attribute__((packed));

struct TCPHeader {
    enum Flags {
        // Sender reduced rate
        CongestionWindowReduced = 1 << 7,
        // Sender received congestion notification
        ECNEcho = 1 << 6,
        // There is priority data in the thing
        URG = 1 << 5,
        ACK = 1 << 4,
        PSH = 1 << 3,
        RST = 1 << 2,
        SYN = 1 << 1,
        FIN = 1,
    };

    NetworkOrdered<u16> source_port;
    NetworkOrdered<u16> dest_port;
    NetworkOrdered<u32> seq_num;
    NetworkOrdered<u32> ack_num;
    u8 _reserved : 4;
    // Header length in 32 bit words
    u8 header_length : 4;
    // See TCPHeader::Flags
    u8 flags;
    // The amount of bytes a receiver can accept
    NetworkOrdered<u16> window_size;
    NetworkOrdered<u16> checksum;
    // Where the priority data is in the stream
    NetworkOrdered<u16> urgent_pointer;
    u8 options[];
} __attribute__((packed));

class EthernetBuffer {
public:
    static constexpr int HEADER_SIZE = sizeof(EthernetHeader);

    static EthernetBuffer FromVLBuffer(VLBuffer&&);

    EthernetHeader& GetEthernetHeader();
    VLBufferView GetPayload();

    VLBuffer Release() { return std::move(m_buffer); };

    void SetupEthConnection(const EthernetConnection&);
    void SetSourceMac(const EthernetMAC& mac);
    void SetDestMac(const EthernetMAC& mac);
    void SetEthernetType(u16 type);

    void Hexdump() { m_buffer.Hexdump(); }

    size_t Size() const { return m_buffer.Size(); }

    explicit EthernetBuffer(VLBuffer&& buf)
        : m_buffer(std::move(buf))
    {
    }

protected:
    VLBuffer m_buffer;
};

class ARPBuffer : public EthernetBuffer {
public:
    static constexpr int HEADER_SIZE = sizeof(EthernetHeader) + sizeof(ARPHeader);

    static ARPBuffer FromVLBuffer(VLBuffer&&);
    explicit ARPBuffer(VLBuffer&& buf)
        : EthernetBuffer(std::move(buf))
    {
    }

    ARPHeader& GetARPHeader();
    VLBufferView GetPayload();

    void SetupARPHeader(arp_hardware, arp_proto);
    void SetARPOpcode(u16 opcode);
};

class IPv4Buffer : public EthernetBuffer {
public:
    static constexpr int HEADER_SIZE = sizeof(EthernetHeader) + sizeof(IPv4Header);

    static IPv4Buffer WithSize(size_t);
    static IPv4Buffer FromVLBuffer(VLBuffer&&);
    explicit IPv4Buffer(VLBuffer&& buf)
        : EthernetBuffer(std::move(buf))
    {
    }

    IPv4Header& GetIPv4Header();
    VLBufferView GetPayload();

    u16 RunIPHeaderChecksum();

    void SetupIPConnection(const IPv4Connection&);
    void CopyIPHeader(const IPv4Header&);
};

class ICMPv4Buffer : public IPv4Buffer {
public:
    static constexpr int HEADER_SIZE = sizeof(EthernetHeader) + sizeof(IPv4Header) + sizeof(ICMPv4Header);

    static ICMPv4Buffer MakeBuffer(size_t payload_size);

    static ICMPv4Buffer FromVLBuffer(VLBuffer&&);
    explicit ICMPv4Buffer(VLBuffer&& buf)
        : IPv4Buffer(std::move(buf))
    {
    }

    ICMPv4Header& GetICMPv4Header();
    VLBufferView GetPayload();

    void ApplyICMPv4Checksum();
    u16 RunICMPv4Checksum();
};
