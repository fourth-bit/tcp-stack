#include <arpa/inet.h>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <netdb.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>

#include <iostream>
#include <unordered_map>

#include <linux/if.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_tun.h>
#include <thread>

#include "NetworkDevice.h"
#include "NetworkOrder.h"
#include "TimerManager.h"

std::unique_ptr<NetworkDevice> the_net_dev;

struct ethernet_header {
    // Destination mac address
    uint8_t dest_mac[6];
    // Source mac address
    uint8_t src_mac[6];
    // This field contains the type of payload (IPv4, IPv6, ARP)
    NetworkOrdered<uint16_t> ethernet_type;

    // The data sent in the format of the specified ethernet_type
    uint8_t payload[];
} __attribute__((packed));

// Header for the address resolution protocol
struct arp_header {
    // This is the link layer type (ethernet, wifi)
    NetworkOrdered<uint16_t> hwtype;
    // This is the protocol type (IPv4)
    NetworkOrdered<uint16_t> protype;
    // This is like mac address size
    uint8_t hwsize;
    // This is like IP address size
    uint8_t prosize;
    // Request or Reply
    NetworkOrdered<uint16_t> opcode;

    // The data
    uint8_t data[];
} __attribute__((packed));

struct arp_ipv4 {
    uint8_t src_mac[6];
    uint32_t src_ip;
    uint8_t dest_mac[6];
    uint32_t dest_ip;
} __attribute__((packed));

struct ipv4_header {
    enum ProtocolType {
        ICMP = 1,
        TCP = 6,
    };

    // Length of the header in 32-bit words. Always >= 5
    uint8_t header_length : 4;
    // IP version (always 4)
    uint8_t version : 4;
    // From the first ip version. Tells about quality of service
    uint8_t type_of_service;
    // Length of the entire packet (bytes)
    NetworkOrdered<uint16_t> total_length;
    // Used in packet fragmentation. Is the fragment number
    NetworkOrdered<uint16_t> id;
    // Control flags. Is fragmentation allowed? Last Fragment?
    // More Fragments?
    // Fixme: This is wrong order between flags and frag offset
    uint16_t flags : 3;
    // Where is the fragment in the entire message
    uint16_t fragment_offset : 13;
    // This field is decrement every hop a packet take. When it reaches 0, the
    // packet is dropped
    uint8_t time_to_live;
    // What is the format of the payload: (e.g TCP, UDP, ICMP)
    uint8_t protocol;
    // Verifies integrity
    uint16_t header_checksum;
    uint32_t source_ip;
    uint32_t dest_ip;
    uint8_t options_and_payload[];
} __attribute__((packed));

struct icmp_v4 {
    enum RequestType {
        EchoResp = 0,
        DestUnreachable = 3,
        EchoReq = 8,
    };

    // Purpose of the message (e.g. Echo Request)
    uint8_t type;
    // Meaning of the message like destination unreachable
    uint8_t code;
    // Uses the IP checksum to verify the header
    // Payload in included in the calculation of the checksum
    uint16_t checksum;
    uint8_t data[];
} __attribute__((packed));

struct icmp_v4_echo {
    // Sender sets this to know what process is meant to receive it
    NetworkOrdered<uint16_t> id;
    // The ping number
    NetworkOrdered<uint16_t> seq;
    // Optional field. Can contain time information
    uint8_t data[];
} __attribute__((packed));

struct icmp_v4_destination_unreachable {
    uint8_t _unused;
    // Length of original data
    uint8_t len;
    // Depends of the ICMP code
    NetworkOrdered<uint16_t> var;
    // Original data
    uint8_t data[];
} __attribute__((packed));

struct tcp_header {
    enum connection_flags {
        // Sender reduced rate
        CongestionWindowReduced = 1 << 7,
        // Sender received congestion notification
        ECNEcho = 1 << 6,
        // There is priority data in the thing
        Urgent = 1 << 5,
        ACK = 1 << 4,
        PSH = 1 << 3,
        RST = 1 << 2,
        SYN = 1 << 1,
        FIN = 1,
    };

    NetworkOrdered<uint16_t> source_port;
    NetworkOrdered<uint16_t> dest_port;
    NetworkOrdered<uint32_t> seq_num;
    NetworkOrdered<uint32_t> ack_num;
    uint8_t _reserved : 4;
    // Header length in 32 bit words
    uint8_t header_length : 4;
    // See tcp_header::connection_flags
    uint8_t flags;
    // The amount of bytes a receiver can accept
    NetworkOrdered<uint16_t> window_size;
    uint16_t checksum;
    // Where the priority data is in the stream
    NetworkOrdered<uint16_t> urgent_pointer;
    uint8_t data[];
} __attribute__((packed));

struct TCPState {
    enum {
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
    } state;

    struct {
        // Receive Next
        uint32_t NXT;
        // Receive Window
        uint16_t WND;
        // Receive Urgent Pointer
        uint16_t UP;
        // Initial Receive Sequence Number
        uint32_t IRS;
    } RCV;

    struct {
        // Send Unacknowledged
        uint32_t UNA;
        // Send Next
        uint32_t NXT;
        // Send Window
        uint16_t WND;
        // Send Urgent Pointer
        uint16_t UP;
        // Segment Sequence Number Used For Last Window Update
        uint32_t WL1;
        // Segment Acknowledgement Number Used For Last Window Update
        uint32_t WL2;
        // Initial Send Sequence Number
        uint32_t ISS;
    } SND;
};

struct TCPSegment {
    // Segment Sequence Number
    uint32_t SEQ;
    // Segment Acknowledgement Number
    uint32_t ACK;
    // Segment Length
    uint32_t len;
    // Segment Window
    uint32_t WND;
    // Segment Urgent Pointer;
    uint32_t UP;
    // Segment Precedence Value
    uint32_t PRC;
};

struct network_device {
    uint32_t ip;
    uint8_t mac[6];
    int fd;
};

static network_device device;

uint16_t checksum(void* addr, int count);
void print_hexdump(uint8_t* buffer, size_t len);
void ipv4_send(ethernet_header* source, ipv4_header::ProtocolType, uint8_t* data, size_t length);
void resolve_arp(ethernet_header* sent_hdr);
void resolve_icmp(ethernet_header* header);
void resolve_ipv4(ethernet_header* header);
void resolve_tcp(ethernet_header* header);
void runCustomTCPClient();
void runSystemTCPServer();
int tun_alloc(char* dev);

void print_hexdump(uint8_t* buffer, size_t len)
{
    printf("Printing hexdump:\n");
    for (size_t i = 0; i < len; i++) {
        if (i % 8 == 0)
            printf("\n");
        printf("%02x ", buffer[i]);
    }

    printf("\n");
}

void runSystemTCPServer()
{
    struct addrinfo hints {
    }, *res;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    getaddrinfo(nullptr, "8001", &hints, &res);

    int fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);

    bind(fd, res->ai_addr, res->ai_addrlen);
    listen(fd, 1);

    freeaddrinfo(res);

    int recv_fd = accept(fd, nullptr, nullptr);
    close(recv_fd);

    close(fd);
}

uint16_t checksum(void* addr, int count)
{
    /* Compute Internet Checksum for "count" bytes
     *         beginning at location "addr".
     * Taken from https://tools.ietf.org/html/rfc1071
     */

    uint32_t sum = 0;
    auto* ptr = (uint16_t*)addr;

    while (count > 1) {
        /*  This is the inner loop */
        sum += *ptr++;
        count -= 2;
    }

    /*  Add left-over byte, if any */
    if (count > 0)
        sum += *(uint8_t*)ptr;

    /*  Fold 32-bit sum to 16 bits */
    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);

    return ~sum;
}

// Shamelessly taken from: https://www.saminiir.com/lets-code-tcp-ip-stack-1-ethernet-arp/
int tun_alloc(char* dev)
{
    struct ifreq ifr {
    };
    int fd, err;

    if ((fd = open("/dev/net/tap0", O_RDWR)) < 0) {
        std::fprintf(stderr, "Cannot open TUN/TAP dev");
        exit(1);
    }

    /* Flags: IFF_TUN   - TUN device (no Ethernet headers)
     *        IFF_TAP   - TAP device
     *
     *        IFF_NO_PI - Do not provide packet information
     */
    ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
    if (*dev) {
        strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    }

    if ((err = ioctl(fd, TUNSETIFF, (void*)&ifr)) < 0) {
        std::fprintf(stderr, "ERR: Could not ioctl tun: %s\n", strerror(errno));
        close(fd);
        return err;
    }

    strcpy(dev, ifr.ifr_name);
    return fd;
}

void resolve_arp(ethernet_header* sent_hdr)
{
    // Fixme: Only IPv4 support here
    static std::unordered_map<uint32_t, std::array<uint8_t, 6>> translation_table;

    enum arp_hardware : uint16_t {
        ethernet = 0x0001,
    };
    enum arp_proto : uint16_t {
        IPv4 = 0x0800,
    };

    std::printf("Resolving ARP\n");

    const arp_hardware known_arp_hardware_types[] = { arp_hardware::ethernet };
    const arp_proto known_arp_proto_types[] = { arp_proto::IPv4 };

    auto* header = reinterpret_cast<arp_header*>(sent_hdr->payload);

    // Fixme: Make this ... you know ... correct
    if (header->hwtype != known_arp_hardware_types[0]) {
        std::fprintf(stderr, "ERR: Unknown ARP hardware type: %d", (uint16_t)header->hwtype);
    }

    if (header->protype != known_arp_proto_types[0]) {
        std::fprintf(stderr, "ERR: Unknown ARP protocol type: %d", (uint16_t)header->protype);
    }

    auto* arp_body = reinterpret_cast<arp_ipv4*>(header->data);

    // The shenanigans with the merge flag do not matter
    auto& mapped_value = translation_table[arp_body->src_ip];
    std::copy(std::begin(arp_body->src_mac), std::end(arp_body->src_mac), mapped_value.begin());

    if (arp_body->dest_ip != device.ip) {
        std::printf("ARP not for us\n");
        return;
    }

    switch (header->opcode) {
    case 0x001: { // Arp Request Fixme: Refactor to struct
        size_t len = sizeof(ethernet_header)
            + sizeof(arp_header)
            + sizeof(arp_ipv4);

        auto* resp_header = (ethernet_header*)malloc(len);
        resp_header->ethernet_type = ETH_P_ARP;
        std::copy(std::begin(device.mac), std::end(device.mac), std::begin(resp_header->src_mac));
        std::copy(std::begin(arp_body->src_mac), std::end(arp_body->src_mac), std::begin(resp_header->dest_mac));

        auto* arp_resp = reinterpret_cast<arp_header*>((intptr_t)resp_header + sizeof(ethernet_header));
        arp_resp->hwtype = header->hwtype;
        arp_resp->protype = header->protype;
        arp_resp->hwsize = header->hwsize;
        arp_resp->prosize = header->prosize;

        arp_resp->opcode = 0x002; // ARP Response

        auto* arp_resp_body = reinterpret_cast<arp_ipv4*>((intptr_t)arp_resp + sizeof(arp_header));
        arp_resp_body->src_ip = device.ip;
        arp_resp_body->dest_ip = arp_body->src_ip;
        std::copy(std::begin(arp_body->src_mac), std::end(arp_body->src_mac), std::begin(arp_resp_body->dest_mac));
        std::copy(std::begin(device.mac), std::end(device.mac), std::begin(arp_resp_body->src_mac));

        write(device.fd, resp_header, len);
        break;
    }
    }
}

void resolve_icmp(ethernet_header* header)
{
    std::printf("Resolving ICMP\n");

    auto* ipv4_hdr = reinterpret_cast<ipv4_header*>(header->payload);
    // FIXME: IP options will mess this up
    auto* icmp_hdr = reinterpret_cast<icmp_v4*>(ipv4_hdr->options_and_payload);

    // TODO: checksum

    switch (icmp_hdr->type) {
    case icmp_v4::EchoReq: // Echo Request
    {
        std::printf("Resolving ICMP echo\n");

        auto* echo_req = reinterpret_cast<icmp_v4_echo*>(icmp_hdr->data);

        // size_t len = sizeof(icmp_v4) + sizeof(icmp_v4_echo);
        size_t len = ipv4_hdr->total_length - (ipv4_hdr->header_length * 4);
        auto* new_header = (icmp_v4*)malloc(len);

        new_header->type = icmp_v4::EchoResp;
        new_header->code = icmp_hdr->code;
        // Actual checksum comes later
        new_header->checksum = 0;

        auto* echo_resp = reinterpret_cast<icmp_v4_echo*>(new_header->data);
        echo_resp->id = echo_req->id;
        echo_resp->seq = echo_req->seq;
        std::memcpy(echo_resp->data, echo_req->data, len - sizeof(icmp_v4) - 4);

        new_header->checksum = checksum(new_header, (int)len);

        ipv4_send(header, ipv4_header::ICMP, reinterpret_cast<uint8_t*>(new_header), len);

        std::printf("ICMP Echo Response sent\n");
        break;
    }
    }
}

TCPSegment segment_fromheader(tcp_header* hdr)
{
    return TCPSegment {
        .SEQ = hdr->seq_num,
        .ACK = hdr->ack_num,
    };
}

void tcp_send(uint8_t flags, uint32_t seq_num, uint32_t ack_num, tcp_header* tcp_hdr, ethernet_header* header, uint8_t* data, size_t len)
{
    tcp_header new_header = {
        .source_port = tcp_hdr->dest_port,
        .dest_port = tcp_hdr->source_port,
        .seq_num = seq_num,
        .ack_num = ack_num,
        .header_length = 5,
        .flags = flags,
        .window_size = tcp_hdr->window_size,
        .checksum = 0, // As usual we handle this later
        .urgent_pointer = 0,
    };

    ipv4_send(header, ipv4_header::TCP, (uint8_t*)&new_header, sizeof(tcp_header));
}

void resolve_tcp(ethernet_header* header)
{
    // This implementation follows RFC 793: Segment Arrived

    // TODO: Make this a client as well
    const uint16_t open_ports[] = { 1337 };
    static TCPState state = { TCPState::LISTEN };

    auto* ip_hdr = reinterpret_cast<ipv4_header*>(header->payload);
    auto* tcp_hdr = reinterpret_cast<tcp_header*>((intptr_t)ip_hdr + ip_hdr->header_length * 4);

    auto seg = segment_fromheader(tcp_hdr);

    // FIXME
    if (tcp_hdr->dest_port != open_ports[0]) {
        std::fprintf(stderr, "Received TCP request to unopened port: %d\n", (uint16_t)tcp_hdr->dest_port);
        return;
    }

    // TODO: TCPState::CLOSED

    if (state.state == TCPState::LISTEN) {
        // Look for Reset
        if (tcp_hdr->flags & tcp_header::RST) {
            // An incoming RST should be ignored.  Return.
            return;
        }

        // Then ACK
        if (tcp_hdr->flags & tcp_header::ACK) {
            // An ACK in Listen State is ill-formed
            // Send RST with SEQ equal to the ACK number

            tcp_send(tcp_header::RST, seg.ACK, 0, tcp_hdr, header, nullptr, 0);

            return;
        }

        // TODO: If the SYN bit is set, check the security.  If the
        //        security/compartment on the incoming segment does not exactly
        //        match the security/compartment in the TCB then send a reset and
        //        return.
        //        And Friends

        state.RCV.IRS = tcp_hdr->seq_num;
        state.RCV.NXT = tcp_hdr->seq_num + 1;
        state.RCV.WND = tcp_hdr->window_size;

        state.SND.ISS = 900;
        state.SND.NXT = state.SND.ISS + 1;
        state.SND.UNA = state.SND.ISS;
        state.SND.WND = tcp_hdr->window_size;

        tcp_send(tcp_header::SYN | tcp_header::ACK, state.SND.ISS, tcp_hdr->ack_num + 1, tcp_hdr, header, nullptr, 0);

        state.state = TCPState::SYN_RCVD;

        // TODO: Look at the RFC
        return;
    }

    if (state.state == TCPState::SYN_SENT) {
        // TODO
    }

    // FIXME: More spec compliant
    // First check the sequence number
    if (tcp_hdr->seq_num < state.RCV.NXT || tcp_hdr->seq_num > state.RCV.NXT + state.RCV.WND) {
        // Drop packet
        return;
    }

    // Check RST bit
    if (tcp_hdr->flags & tcp_header::RST) {
        switch (state.state) {
        case TCPState::SYN_RCVD:
            // Assume that we came from passive OPEN
            state.state = TCPState::LISTEN;
            return;
        case TCPState::ESTABLISHED:
        case TCPState::FIN_WAIT_1:
        case TCPState::FIN_WAIT_2:
        case TCPState::CLOSE_WAIT:
            // TODO: If the RST bit is set then, any outstanding RECEIVEs and SEND
            //        should receive "reset" responses.  All segment queues should be
            //        flushed.  Users should also receive an unsolicited general
            //        "connection reset" signal.  Enter the CLOSED state, delete the
            //        TCB, and return.

            break;
        case TCPState::CLOSING:
        case TCPState::LAST_ACK:
        case TCPState::TIME_WAIT:
            // TODO: Delete TCB
            state.state = TCPState::CLOSED;

            break;
        }
    }

    // TODO: third check security and precedence

    // Check the SYN bit
    if (tcp_hdr->flags & tcp_header::SYN) {
        switch (state.state) {
        case TCPState::SYN_RCVD:
        case TCPState::ESTABLISHED:
        case TCPState::FIN_WAIT_1:
        case TCPState::FIN_WAIT_2:
        case TCPState::CLOSE_WAIT:
        case TCPState::CLOSING:
        case TCPState::LAST_ACK:
        case TCPState::TIME_WAIT:
            // TODO: Page 71 of RFC 793
            break;
        }
    }

    if (!(tcp_hdr->flags & tcp_header::ACK)) {
        // Drop the segment
        return;
    }

    switch (state.state) {
    case TCPState::SYN_RCVD:
        // If the ACK is Unacceptable
        if (state.SND.UNA < seg.ACK || seg.ACK > state.SND.NXT) {
            // Send a reset
            tcp_send(tcp_header::RST, seg.ACK, 0, tcp_hdr, header, nullptr, 0);
            return;
        }

        state.state = TCPState::ESTABLISHED;
        // Fall through the ESTABLISHED
    case TCPState::ESTABLISHED:
        if (state.SND.UNA < seg.ACK && seg.ACK <= state.SND.NXT) {
            state.SND.UNA = seg.ACK;
            // TODO: Any segments on the retransmission queue which are thereby
            //       entirely acknowledged are removed.
        } else if (seg.ACK < state.SND.UNA) {
            // Ignore: no-op
        } else if (seg.ACK > state.SND.NXT) {
            // TODO: Send ACK, drop segment, return

            return;
        }

        if (state.SND.UNA < seg.ACK && seg.ACK <= state.SND.NXT) {
            // TODO: Update SEND window
        }
    }

    if (tcp_hdr->flags & tcp_header::Urgent) {
        // TODO
    }

    // Process Transmitted Data
    switch (state.state) {
    case TCPState::ESTABLISHED:
    case TCPState::FIN_WAIT_1:
    case TCPState::FIN_WAIT_2: {
        // Move the data to the buffer
        size_t length = ip_hdr->total_length - ip_hdr->header_length * 4 - tcp_hdr->header_length * 4;

        auto* buffer = (char*)malloc(length + 1);
        memcpy(buffer, tcp_hdr->data, length);
        buffer[length] = '\0';

        std::cout << buffer << std::endl;

        free(buffer);

        // Send back an ACK
        state.RCV.NXT += seg.len;
        tcp_send(tcp_header::ACK, state.SND.NXT, state.RCV.NXT, tcp_hdr, header, nullptr, 0);

        break;
    }
        // Ignore it in the other cases
    }

    if (tcp_hdr->flags & tcp_header::FIN) {
        if (state.state == TCPState::CLOSED || state.state == TCPState::LISTEN || state.state == TCPState::SYN_SENT) {
            // Drop segment
            return;
        }

        // Advance over FIN
        state.RCV.NXT += 1;
        tcp_send(tcp_header::FIN | tcp_header::ACK, state.SND.NXT, state.RCV.NXT, tcp_hdr, header, nullptr, 0);

        switch (state.state) {
        case TCPState::SYN_RCVD:
        case TCPState::ESTABLISHED:
            state.state = TCPState::CLOSE_WAIT;
            break;
        case TCPState::FIN_WAIT_1:
        case TCPState::FIN_WAIT_2:
        case TCPState::CLOSE_WAIT:
        case TCPState::CLOSING:
        case TCPState::LAST_ACK:
        case TCPState::TIME_WAIT:
            // Figure out what to do
            break;
        }
    }

    /*
    switch (state.state) {
    case TCPState::CLOSED:
        // TODO: error
        break;
    case TCPState::LISTEN: {
        if (tcp_hdr->flags != tcp_header::SYN) {
            std::fprintf(stderr, "Received TCP packet with flags not equal to SYN in LISTEN state. Received: %d. Dropping\n", tcp_hdr->flags);
            break;
        }

        state.RCV.IRS = tcp_hdr->seq_num;
        state.RCV.NXT = tcp_hdr->seq_num + 1;
        state.RCV.WND = tcp_hdr->window_size;

        state.SND.ISS = 900;
        state.SND.NXT = state.SND.ISS + 1;
        state.SND.UNA = state.SND.ISS;
        state.SND.WND = tcp_hdr->window_size;

        // Now we send SYN, ACK
        tcp_send(tcp_header::SYN | tcp_header::ACK, state.SND.ISS, tcp_hdr->ack_num + 1, tcp_hdr, header, nullptr, 0);

        break;
    }
    case TCPState::SYN_SENT:
        break;
    case TCPState::SYN_RCVD: {
        if (tcp_hdr->flags == tcp_header::ACK) {
            std::fprintf(stderr, "Received TCP packet with flags not equal to ACK in SYN RCVD state. Received %d. Dropping\n", tcp_hdr->flags);
        }

        state.SND.UNA++;

        /*tcp_header new_header = {
            .source_port = tcp_hdr->dest_port,
            .dest_port = tcp_hdr->source_port,
            .seq_num = ++state.seq_num,
            .ack_num = ++state.ack_num,
            .header_length = 5,
            .flags = 0,
        };* /

        state.state = TCPState::ESTABLISHED;
        break;
    }
    case TCPState::ESTABLISHED: {
        // Receiving Data
        if (tcp_hdr->seq_num < state.RCV.NXT || tcp_hdr->seq_num > state.RCV.NXT + state.RCV.WND) {
            // Drop packet
            break;
        }
    }
    case TCPState::CLOSE_WAIT:
    case TCPState::LAST_ACK:
    case TCPState::FIN_WAIT_1:
    case TCPState::FIN_WAIT_2:
    case TCPState::CLOSING:
    case TCPState::TIME_WAIT:
        break;
    }*/
}

void resolve_ipv4(ethernet_header* header)
{
    std::printf("Resolving IPv4\n");

    auto* ip_header = reinterpret_cast<ipv4_header*>(header->payload);

    if (ip_header->version != 4) {
        std::fprintf(stderr, "Received IPv4 packet with version not equal to 4. Version is: %d. Dropping\n", ip_header->version);
        return;
    }

    if (ip_header->header_length < 5) {
        std::fprintf(stderr, "Received IPv4 packet with header length less than 5. Dropping\n");
        return;
    }

    if (ip_header->time_to_live == 0) {
        std::fprintf(stderr, "Received IPv4 packet with Time To Live equal to 0. Dropping\n");
        return;
    }

    // Header length counts 32 byte words
    uint16_t csum = checksum((void*)ip_header, ip_header->header_length * 4);
    if (csum != 0) {
        std::fprintf(stderr, "Received IPv4 packet with invalid checksum. Dropping\n");
        return;
    }

    switch (ip_header->protocol) {
    case ipv4_header::ICMP: // ICMP
        resolve_icmp(header);
        break;
    case ipv4_header::TCP:
        resolve_tcp(header);
        break;
    }
}

void ipv4_send(ethernet_header* source, ipv4_header::ProtocolType protocol, uint8_t* data, size_t length)
{
    size_t len = sizeof(ethernet_header) + sizeof(ipv4_header) + length;
    auto* eth_header = (ethernet_header*)malloc(len);
    std::copy(std::begin(device.mac), std::end(device.mac), std::begin(eth_header->src_mac));
    std::copy(std::begin(source->src_mac), std::end(source->src_mac), std::begin(eth_header->dest_mac));
    eth_header->ethernet_type = ETH_P_IP;

    auto* header = reinterpret_cast<ipv4_header*>(eth_header->payload);
    auto* source_header = reinterpret_cast<ipv4_header*>(source->payload);

    header->version = 4;
    header->header_length = 5;
    // I don't know what to put here
    header->type_of_service = source_header->type_of_service;
    header->total_length = len - sizeof(ethernet_header);
    header->id = source_header->id;
    header->flags = 0b000;
    header->fragment_offset = 0;
    header->time_to_live = 64; // 64 is the standard
    header->protocol = protocol;
    // Calculate later
    header->header_checksum = 0;
    header->source_ip = device.ip;
    header->dest_ip = source_header->source_ip;

    header->header_checksum = checksum(header, header->header_length * 4);

    // memcpy(dest, src, len);
    std::memcpy(header->options_and_payload, data, length);

    write(device.fd, (void*)eth_header, len);
}

void runCustomTCPClient()
{
    char buf[100];
    char* dev = (char*)calloc(10, sizeof(char));
    int tun_fd = tun_alloc(dev);

    printf("tun_dev: %s\n", dev);

    snprintf(buf, 100, "ip link set dev %s up", dev);
    system(buf);

    snprintf(buf, 100, "ip route add dev %s 10.0.0.0/24", dev);
    system(buf);

    snprintf(buf, 100, "ip address add dev %s local 10.0.0.5/24", dev);
    system(buf);

    // Set the ip
    inet_pton(AF_INET, "10.0.0.4", &device.ip);
    // 00:0c:29:6d:50:25
    device.mac[0] = 0x00;
    device.mac[1] = 0x0c;
    device.mac[2] = 0x29;
    device.mac[3] = 0x6d;
    device.mac[4] = 0x50;
    device.mac[5] = 0x25;

    device.fd = tun_fd;

    for (;;) {
        uint8_t buffer[4096];

        size_t bytes = read(tun_fd, buffer, 4096);
        if (bytes < 0) {
            std::fprintf(stderr, "ERR: Could not read from the tun_fd: %s", strerror(errno));
            close(tun_fd);
            return;
        }

        std::printf("Received transmission\n");
        print_hexdump(buffer, bytes);

        auto* header = reinterpret_cast<ethernet_header*>(buffer); // Buffer decays to pointer

        switch (header->ethernet_type) {
        case ETH_P_ARP:
            resolve_arp(header);
            break;
        case ETH_P_IP:
            resolve_ipv4(header);
            break;
        default:
            break;
        }
    }
}

void runNewCustomClient()
{
    using namespace std::chrono_literals;

    // Make a socket for ioctl
    // Use the way to make sure that we get a correct result
    int fd = socket(AF_INET, SOCK_STREAM, 0);

    // Initialize an interface request with the name set to eth0
    struct ifreq ifr { };
    memcpy(ifr.ifr_name, "eth0", sizeof("eth0"));

    // Get the mac address using the interface request
    ioctl(fd, SIOCGIFHWADDR, &ifr);
    u8* hw_addr = (u8*)ifr.ifr_hwaddr.sa_data;

    // Copy that data to a stack array
    EthernetMAC mac_address {};
    std::copy(hw_addr, hw_addr + 6, mac_address.begin());

    // Get the IP address using the same request
    ioctl(fd, SIOCGIFADDR, &ifr);
    auto* ipaddr = (struct sockaddr_in*)&ifr.ifr_addr;

    // We don't need the socket anymore
    close(fd);

    // Grab the ip address as an int from the sockaddr_in
    auto ip_address = NetworkOrdered<u32>::WithNetworkOrder(ipaddr->sin_addr.s_addr);

    the_net_dev = std::make_unique<NetworkDevice>(
        mac_address,
        IPv4Address(ip_address),
        16,
        IPv4Address::FromString("172.18.0.1").value());

    // Use another thread so we can continue here
    std::thread th([&]() { the_net_dev->Listen(); });

    std::cout << IPv4Address(ip_address) << std::endl;

//    for (int i = 0; i < 10; i++) {
//        auto address = IPv4Address::FromString("172.18.0.7");
//        auto maybe_us = the_net_dev->GetICMPManager().SendEchoRequest(*address);
//        if (maybe_us) {
//            std::cout << "Ping (" << i << ") back in " << maybe_us->count() << "us" << std::endl;
//        } else {
//            std::cout << "Ping (" << i << ") failed" << std::endl;
//        }
//    }

    auto* sock = dynamic_cast<TCPSocket*>(Socket::Create(PROTOCOL::INTERNET, SOCK_TYPE::STREAM));
    sock->Bind(1000);
    auto maybe_target = IPv4Address::FromString("172.18.0.3");
    if (!maybe_target.has_value()) {
        std::cerr << "IPv4Address not well-formed" << std::endl;
        return;
    }
    sock->Connect(NetworkAddress(maybe_target.value()), 1000);
    for (;;) {
        auto maybe_buffer = sock->Read();
        if (maybe_buffer.IsError()) {
            std::cout << "Error in Read " << maybe_buffer.GetError()->ToString() << std::endl;
            continue;
        }

        maybe_buffer.GetResult().Hexdump();
    }
    // sock->Listen();

    for (;;) {
        auto maybe_error = sock->Accept();
        if (maybe_error.IsError()) {
            auto* error = dynamic_cast<SocketError*>(maybe_error.GetError());
            std::cerr << "Could not accept from socket. Code: " << (int)error->code << std::endl;

            if (th.joinable()) {
                th.join();
            }
            return;
        }

        auto result = maybe_error.GetResult();

        auto subsocket = std::unique_ptr<Socket>(result.first);
        auto info = std::unique_ptr<SocketInfo>(result.second);

        auto maybe_read_error = subsocket->Read();
        if (maybe_read_error.IsError()) {
            auto* error = dynamic_cast<SocketError*>(maybe_error.GetError());
            std::cerr << "Could not read from subsocket. Code: " << (int)error->code << std::endl;
            continue;
        }
        auto& buffer = maybe_read_error.GetResult();

        auto* info_raw = dynamic_cast<PortSocketInfo*>(info.get());
        if (info_raw == nullptr) {
            std::cerr << "Unexpected Socket Info Type" << std::endl;
            continue;
        }

        auto [network_addr, port] = *info_raw;
        auto ip = std::get<IPv4Address>(network_addr);

        std::cout << ip << ": ";
        for (size_t i = 0; i < buffer.Size(); i++) {
            std::cout << buffer[i];
        }
        if (buffer.Size() && buffer[buffer.Size() - 1] != '\n') {
            std::cout << std::endl;
        } else {
            std::cout << std::flush;
        }

        u64 written = 0;
        VLBufferView view = buffer.AsView();
        do {
            written += subsocket->Write(view.SubBuffer(written));
        } while (written != buffer.Size());

    }

    if (th.joinable()) {
        th.join();
    }
}

int main()
{
#if 0
    int fd = socket(AF_INET, SOCK_STREAM, 0);

    struct ifreq ifr {};

    memcpy(ifr.ifr_name, "eth0", sizeof("eth0"));

    ioctl(fd, SIOCGIFHWADDR, &ifr);

    u8* mac = (u8*)ifr.ifr_hwaddr.sa_data;
    printf("%02X:%02X:%02X:%02X:%02X:%02X\n",
        mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);

    ioctl(fd, SIOCGIFADDR, &ifr);

    auto* ipaddr = (struct sockaddr_in*)&ifr.ifr_addr;
    printf("%s\n",inet_ntoa(ipaddr->sin_addr));

    close(fd);

#elif 0
    int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

    struct ifreq ifr { };

    memcpy(ifr.ifr_name, "eth0", sizeof("eth0"));

    int res = ioctl(fd, SIOCGIFINDEX, &ifr);
    if (res != 0) {
        return 1;
    }

    int index = ifr.ifr_ifindex;
    std::cout << index << '\n';

    struct sockaddr_ll sll { };

    sll.sll_ifindex = index;
    sll.sll_family = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_ALL);

    int result = bind(fd, reinterpret_cast<sockaddr*>(&sll), (socklen_t)sizeof(sockaddr_ll));
    if (result != 0) {
        perror("bind");
        return 2;
    }

    listen(fd, 10);

    while (true) {
        auto buf = VLBuffer::WithSize(1528);

        ssize_t bytes = read(fd, buf.Data(), buf.Size());
        if (bytes < 0) {
            return 3;
        }

        buf.Resize(bytes);

        buf.Hexdump();
    }
#elif 0
    VLBuffer vlbuf = VLBuffer::WithSize(42);
    std::array<u8, 42> data = { 0x02, 0x42, 0xac, 0x12, 0x00, 0x03, 0x02, 0x42,
        0x97, 0x41, 0xce, 0x47, 0x08, 0x06, 0x00, 0x01,
        0x08, 0x00, 0x06, 0x04, 0x00, 0x02, 0x02, 0x42,
        0x97, 0x41, 0xce, 0x47, 0xac, 0x12, 0x00, 0x01,
        0x02, 0x42, 0xac, 0x12, 0x00, 0x03, 0xac, 0x12,
        0x00, 0x03 };

    std::copy(data.begin(), data.end(), vlbuf.Data());

    NetworkBuffer buffer = NetworkBuffer(std::move(vlbuf));
    auto& eth_layer = buffer.AddLayer<LayerType::Ethernet>(sizeof(EthernetHeader));
    auto& arp_layer = buffer.AddLayer<LayerType::ARP>(sizeof(ARPHeader));

    auto& header = arp_layer.GetHeader();
    std::cout << header.hwtype << std::endl;

    auto payload = buffer.GetPayload<ARP_IPv4>();
#elif 0
    CircularBuffer buffer { 32 };

    VLBuffer buffer_to_write = VLBuffer::WithSize(18);
    for (char x = 'a'; x < 'a' + 18; x++) {
        buffer_to_write[x-'a'] = x;
    }

    buffer.Write(buffer_to_write.AsView());
    auto data = buffer.Read(14);
    data.Hexdump();

    buffer.Write(buffer_to_write.AsView());
    data = buffer.Read(100);
    data.Hexdump();

    buffer.Write(buffer_to_write.AsView());
    buffer.Write(buffer_to_write.AsView().ShrinkEnd(buffer.RemainingSpace()));
    data = buffer.Read(32);
    data.Hexdump();

#elif 1
    using namespace std::chrono_literals;

    TimerManager manager;

    manager.AddTimer(20ms, [](){
        std::cout << "Timer 1 Fired" << std::endl;
    });
    manager.AddTimer(200ms, [](){
        std::cout << "Timer 2 Fired" << std::endl;
    });
    manager.AddTimer(2ms, [](){
        std::cout << "Timer 3 Fired" << std::endl;
    });

    std::this_thread::sleep_for(1s);

#else
    /*system("rm /dev/net/tap0");

    const char* tmp_filename_ = "/dev/net/tap0";

    // Create a temporary file node for use as a TUN interface.
    // Device 10, 200 is the device code for a TAP/TUN device.
    // See https://www.kernel.org/doc/Documentation/admin-guide/devices.txt
    mkdir("/dev/net", 0777);
    int result = mknod(tmp_filename_, S_IFCHR | 0777, makedev(10, 200));
    if (result < 0) {
        perror("Failed to make temporary file");
    }*/

    /*int pid = fork();
    if (!pid) {
        // In Child
        runSystemTCPServer();
    } else {*/
    // In Parent
    // runCustomTCPClient();
    runNewCustomClient();
    //}

    // close(result);

    return 0;
#endif
}
