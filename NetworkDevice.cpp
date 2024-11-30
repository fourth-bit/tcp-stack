//
// Created by Ryan Wolk on 3/22/22.
//

#include <cerrno>
#include <chrono>
#include <cstring>
#include <fcntl.h>
#include <iostream>
#include <linux/if.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_tun.h>
#include <sstream>
#include <sys/ioctl.h>
#include <unistd.h>
#include <unordered_map>

#include "NetworkBuffer.h"
#include "NetworkDevice.h"

#define USE_TUN 0
#define DEBUG_TRACE_PACKETS
#undef DEBUG_TRACE_PACKETS

struct make_tun_return {
    int fd;
    std::string name;
};

// Shamelessly taken from: https://www.saminiir.com/lets-code-tcp-ip-stack-1-ethernet-arp/
static make_tun_return make_tun()
{
    struct ifreq ifr {
    };
    int fd, err;

    char* dev = (char*)calloc(16, sizeof(char));

    if ((fd = open("/dev/net/tap0", O_RDWR)) < 0) {
        std::fprintf(stderr, "Cannot open TAP dev");
        exit(1);
    }

    /* Flags: IFF_TUN   - TUN device (no Ethernet headers)
     *        IFF_TAP   - TAP device
     *
     *        IFF_NO_PI - Do not provide packet information
     */
    ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
    /*if (*dev) {
        strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    }*/

    if ((err = ioctl(fd, TUNSETIFF, (void*)&ifr)) < 0) {
        std::fprintf(stderr, "ERR: Could not ioctl tap: %s\n", strerror(errno));
        close(fd);
        return { -1, std::string(dev) };
    }

    strcpy(dev, ifr.ifr_name);
    std::string dev_as_string(dev);
    free(dev);
    return { fd, dev_as_string };
}

static int make_packet_socket(std::string device)
{
    int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

    struct ifreq ifr { };
    memcpy(ifr.ifr_name, device.c_str(), device.length() + 1); // + 1 for null terminator

    int res = ioctl(fd, SIOCGIFINDEX, &ifr);
    if (res != 0) {
        perror("ioctl");
        // return 1;
        return -1;
    }

    int index = ifr.ifr_ifindex;

    struct sockaddr_ll sll { };

    sll.sll_ifindex = index;
    sll.sll_family = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_ALL);

    int result = bind(fd, reinterpret_cast<sockaddr*>(&sll), (socklen_t)sizeof(sockaddr_ll));
    if (result != 0) {
        perror("bind");
        // return 2;
        return -1;
    }

    listen(fd, 10);

    return fd;
}

struct parse_ip_return {
    NetworkOrdered<u32> ip;
    u8 subnet_bits;
};

static parse_ip_return parse_ip(const std::string& ip_str)
{
    std::stringstream ss;
    ss << ip_str;

    u32 ip = 0;
    u8 subnet = 0;

    for (int i = 0; i < 4; i++) {
        ip <<= 8;
        u32 next_octet = 0;

        ss >> next_octet;

        if (next_octet > 255) {
            // Todo: Error
        }

        ip += next_octet;

        if (ss.get() != '.') {
            // Todo: Error
        }
    }

    if (ss.get() == '/') {
        ss >> subnet;
        if (subnet > 32) {
            // Todo: Error
        }
    }

    return { ip, subnet };
}

NetworkBuffer EthernetConnection::BuildBufferWith(NetworkBufferConfig& config, size_t payload_size) const
{
    auto buffer = config.BuildBuffer(payload_size);
    EthernetLayer* layer = buffer.GetLayer<LayerType::Ethernet>();

    if (layer) {
        layer->SetSourceMac(source_mac);
        layer->SetDestMac(destination_mac);
        layer->SetEthernetType(connection_type);
    }

    return buffer;
}
NetworkBuffer IPv4Connection::BuildBufferWith(NetworkBufferConfig& config, size_t payload_size) const
{
    auto buffer = eth.BuildBufferWith(config, payload_size);
    IPv4Layer* layer = buffer.GetLayer<LayerType::IPv4>();

    if (layer) {
        layer->SetupConnection(*this);
    }

    return buffer;
}
NetworkConnection IPv4Connection::ToNetworkConnection() const
{
    return {
        .source = { connected_ip },
        .dest = { our_ip },
    };
}
NetworkBuffer IPv6Connection::BuildBufferWith(NetworkBufferConfig& config, size_t payload_size) const
{
    auto buffer = eth.BuildBufferWith(config, payload_size);
    IPv6Layer* layer = buffer.GetLayer<LayerType::IPv6>();

    if (layer) {
        layer->SetupConnection(*this);
    }

    return buffer;
}
NetworkConnection IPv6Connection::ToNetworkConnection() const
{
    return {
        .source = { connected_ip },
        .dest = { our_ip },
    };
}

bool PacketFragments::AddFragment(NetworkBuffer data, bool is_last_frag, u16 offset)
{
    // From RFC 815
    auto payload = data.GetPayload();

    offset *= 8;

    for (auto it = HoleDescriptor.begin(); it != HoleDescriptor.end(); ++it) {
        auto& hole = *it;
        if (offset > hole.fragment_last || offset + payload.Size() < hole.fragment_first) {
            // There has to be an optimization here
            continue;
        }

        if (hole.fragment_last > offset + data.Size() && !is_last_frag) {
            HoleDescriptor.insert(it, { (u16)(offset + payload.Size()), hole.fragment_last });
        }

        if (hole.fragment_first < offset) {
            HoleDescriptor.insert(it, { hole.fragment_first, (u16)(offset - 1) });
        }

        HoleDescriptor.erase(it);
        total_bytes_filled += payload.Size();

        FragmentList.push_back({ std::move(data), offset });

        return true;
    }

    return false;
}
bool PacketFragments::IsFull() const
{
    return HoleDescriptor.empty();
}
NetworkBuffer IPv4Fragments::Release()
{
    // Discard the link-layer level because it doesn't matter
    auto buffer = NetworkBuffer::WithSize(total_bytes_filled + header->header_length * 4);
    auto& ipv4 = buffer.AddLayer<LayerType::IPv4>(header->header_length * 4);

    IPv4Header* buf_header = &ipv4.GetHeader();
    memcpy(buf_header, header, header->header_length * 4);

    auto payload = buffer.GetPayload();

    for (auto& fragment : FragmentList) {
        auto fragment_payload = fragment.fragmentData.GetPayload();
        memcpy(payload.Data() + fragment.offset, fragment_payload.Data(), fragment_payload.Size());
    }

    buf_header->total_length = total_bytes_filled + header->header_length * 4;
    buf_header->header_checksum = ipv4.RunChecksum();

    return buffer;
}
void IPv4Fragments::CopyInHeader(const IPv4Header& other)
{
    header = (IPv4Header*)malloc(other.header_length * 5);

    *header = {
        //.header_length = other.header_length,
        .header_length = 5,
        .version = other.version,
        .type_of_service = other.type_of_service,
        .total_length = other.total_length,
        .id = other.id,
        .flags_and_fragment_offset = 0,
        .time_to_live = other.time_to_live,
        .protocol = other.protocol,
        // Do checksum later
        .header_checksum = 0,
        .source_ip = other.source_ip,
        .dest_ip = other.dest_ip,
    };
}
void IPv6Fragments::CopyInHeader(const IPv6Header& other_header, size_t length)
{
    header = (IPv6Header*)malloc(length - sizeof(IPv6FragmentHeader));
    memcpy(header, &other_header, length - sizeof(IPv6FragmentHeader));
    header_length = length - sizeof(IPv6FragmentHeader);

    // Options have the following format:
    // u8: next header
    // u8: option header length

    if (header->next_header == 44) {
        // This is data that wouldn't have been memcpy'd
        header->next_header = other_header.options[0];
        return;
    }

    size_t option_offset = 0;

    int i = 0;
    while (option_offset < length - sizeof(IPv6Header) - sizeof(IPv6FragmentHeader)) {
        if (i++ > 100) { // Just for sanity so we don't trap ourselves with a malicious incoming packet
            break;
        }

        u8 option_len = header->options[option_offset + 1];
        if (header->options[option_offset] == 44) { // The next header is the fragment header
            // This is data that wouldn't have been memcpy'd
            header->options[option_offset] = other_header.options[option_offset + option_len];
            break;
        }

        option_offset += option_len;
    }
}
NetworkBuffer IPv6Fragments::Release()
{
    // Same logic as IPv4Fragments, only construct the layers for IP and above
    auto buffer = NetworkBuffer::WithSize(total_bytes_filled + header_length);
    auto& ipv6 = buffer.AddLayer<LayerType::IPv6>(header_length);

    IPv6Header* buffer_header = &ipv6.GetHeader();
    memcpy(buffer_header, header, header_length);

    auto payload = buffer.GetPayload();

    for (auto& fragment : FragmentList) {
        auto fragment_payload = fragment.fragmentData.GetPayload();
        memcpy(payload.Data() + fragment.offset, fragment_payload.Data(), fragment_payload.Size());
    }

    buffer_header->payload_length = total_bytes_filled;

    return buffer;
}

NetworkDevice::NetworkDevice(EthernetMAC mac_address,
    IPv4Address ip_addr,
    u8 subnet,
    IPv4Address router,
    IPv6Address ip6,
    size_t mtu)
    : mac(mac_address)
    , m_router(router)
    , icmpManager(this)
    , icmpv6Manager(this)
    , udpManager(this)
    , tcpManager(this)
    , MTU(mtu)
    , m_arp_buffer_config()
    , m_ip6(ip6)
{
    // Fixme: Refactor to a factory

#if USE_TUN
    auto [fd, dev_name] = make_tun();
    tun_fd = fd;

    std::cout << "tun_device: " << dev_name << std::endl;
    // A flush is necessary before a call to system
    char buf[100];

    /*snprintf(buf, 100, "ip route add dev %s 172.18.0.4/16", dev_name.c_str());
    system(buf);

    snprintf(buf, 100, "ip address add dev %s local 10.0.0.5/24", dev_name.c_str());
    system(buf);*/

    snprintf(buf, 100, "ip link set dev %s up", dev_name.c_str());
    system(buf);

    snprintf(buf, 100, "ip link add br0 type bridge");
    system(buf);

    snprintf(buf, 100, "ip link set %s master br0", dev_name.c_str());
    system(buf);

    snprintf(buf, 100, "ip link set dev eth0 down");
    system(buf);

    snprintf(buf, 100, "ip addr flush dev eth0");
    system(buf);

    snprintf(buf, 100, "ip link set dev eth0 up");
    system(buf);

    snprintf(buf, 100, "ip link set eth0 master br0");
    system(buf);

    snprintf(buf, 100, "ip link set br0 up");
    system(buf);

    snprintf(buf, 100, "ip link set dev %s up", dev_name.c_str());
    system(buf);

    snprintf(buf, 100, "ip link set dev %s promisc on", dev_name.c_str());
    system(buf);

    snprintf(buf, 100, "ip link set dev eth0 address 02:42:ac:12:00:09");
    system(buf);

    snprintf(buf, 100, "ip link set dev %s address %s", dev_name.c_str(), mac_address.ToString().c_str());
    system(buf);
#else
    tun_fd = make_packet_socket("eth0");

    system("ip link set dev eth0 address 02:42:ac:00:00:00");
    system("ip address flush dev eth0");
    system("ethtool --offload eth0 rx off tx off sg off tso off ufo off gso off gro off lro off rxvlan off txvlan off rxhash off");
#endif

    ip = ip_addr;
    subnet_mask = SubnetMask(subnet);

    EthernetLayer::Config eth_config {};
    eth_config.src_addr = mac_address;
    m_default_l1_config.AddLayer<LayerType::Ethernet>(eth_config);

    eth_config.connection_type = ETH_P_ARP;
    m_arp_buffer_config.AddLayer<LayerType::Ethernet>(eth_config);
    m_arp_buffer_config.AddLayer<LayerType::ARP>(ARPLayer::Config {});

    eth_config.connection_type = ETH_P_IP;
    IPv4Layer::Config ip4_config {};
    ip4_config.src_ip = ip_addr;
    m_default_ip4_config.AddLayer<LayerType::Ethernet>(eth_config);
    m_default_ip4_config.AddLayer<LayerType::IPv4>(ip4_config);

    eth_config.connection_type = ETH_P_IPV6;
    IPv6Layer::Config ip6_config {};
    ip6_config.src_ip = m_ip6;
    m_default_ip6_config.AddLayer<LayerType::Ethernet>(eth_config);
    m_default_ip6_config.AddLayer<LayerType::IPv6>(ip6_config);

    // Setup A Wakeup for the fragment timeout and listen functions for the
    // (eventual) destructor

    int fds[2];
    pipe(fds);

    m_thread_notify_fd = fds[1];
    m_thread_wakeup_fd = fds[0];

    listen_thread = std::thread([this]() { Listen(); });
    fragment_timeout = std::jthread([this](std::stop_token token) { IPTimeoutFunction(token); });

    // Initialize at end of constructor, otherwise buffer configs are wrong
    icmpv6Manager = ICMPv6Manager { this };
}

NetworkDevice::~NetworkDevice() noexcept
{
    u8 data[2] = { 0x01, 0x00 };
    write(m_thread_notify_fd, data, 2);
    bool res = fragment_timeout.request_stop();
    m_fragment_timeout_cv.notify_all();

    if (listen_thread.joinable()) {
        listen_thread.join();
    }

    if (fragment_timeout.joinable()) {
        fragment_timeout.join();
    }
}

bool NetworkDevice::ShouldRecieveOnMac(const EthernetMAC& destination_mac) const
{
    if (destination_mac.IsBroadcast() || destination_mac == mac) {
        return true;
    }

    // Next we need to check multicast
    // 33:33:IPv6 is an IPv6 Multicast
    if (destination_mac.IsIPv6Multicast(m_ip6)) {
        return true;
    }

    return false;
}

void NetworkDevice::Listen()
{
    fd_set master_read_fds;

    FD_ZERO(&master_read_fds);
    FD_SET(tun_fd, &master_read_fds);
    FD_SET(m_thread_wakeup_fd, &master_read_fds);

    timeval tv { 0, 0 };

    int max_fd = std::max(tun_fd, m_thread_wakeup_fd);

    for (;;) {
        fd_set read_fds = master_read_fds;
        int num_sockets = select(max_fd + 1, &read_fds, nullptr, nullptr, nullptr);

        if (num_sockets < 1) {
            continue;
        } else if (FD_ISSET(m_thread_wakeup_fd, &read_fds)) {
            break;
        }

        // MTU does not consider the ethernet header and one for null terminator
        auto buffer = VLBuffer::WithSize(MTU + sizeof(EthernetHeader) + 1);
        // auto buffer = VLBuffer::WithSize(2000);

        ssize_t bytes = read(tun_fd, buffer.Data(), buffer.Size());
        if (bytes < 0) {
            std::fprintf(stderr, "ERR: Could not read from the tun_fd: %s\n", strerror(errno));
            return;
        }

        // Cut off end of the message
        // Without this the payload will have junk at the end
        buffer.Resize(bytes);

        auto& header = buffer.as<EthernetHeader>();

        // Check if transmission is for us
        if (!ShouldRecieveOnMac(header.dest_mac) || header.src_mac == mac) {
            // std::cout << "Transmission Not For Us" << std::endl;
            // header.dest_mac.Dump();
            continue;
        }

        // buffer.Hexdump();

        // Create the connection struct
        EthernetConnection connection {
            .connection_type = header.ethernet_type,
        };

        std::copy(header.src_mac.begin(), header.src_mac.end(), connection.source_mac.begin());
        std::copy(mac.begin(), mac.end(), connection.destination_mac.begin());

        NetworkBuffer layered_buffer(std::move(buffer));
        layered_buffer.AddLayer(sizeof(EthernetHeader), LayerType::Ethernet);

        // Resolve the transmission
        switch (header.ethernet_type) {
        case ETH_P_ARP:
#ifdef DEBUG_TRACE_PACKETS
            std::cout << "Resolving ARP" << std::endl;
#endif
            ResolveARP(layered_buffer, connection);
            break;
        case ETH_P_IP:
#ifdef DEBUG_TRACE_PACKETS
            std::cout << "Resolving IPv4" << std::endl;
#endif
            ResolveIPv4(layered_buffer, connection);
            break;
        case ETH_P_IPV6:
#ifdef DEBUG_TRACE_PACKETS
            std::cout << "Resolving IPv6" << std::endl;
#endif
            ResolveIPv6(layered_buffer, connection);
            break;
        default:
            break;
        }
    }
}

ARPBuffer NetworkDevice::MakeARPBuffer(size_t payload_size)
{
    return ARPBuffer(VLBuffer::WithSize(sizeof(EthernetHeader) + sizeof(ARPHeader) + payload_size));
}

void NetworkDevice::ResolveARP(NetworkBuffer& buffer, EthernetConnection& connection)
{
    constexpr std::array known_hw { arp_hardware::ethernet };
    constexpr std::array known_proto { arp_proto::IPv4 };

    auto& layer = buffer.AddLayer(sizeof(ARPHeader), LayerType::ARP).As<ARPLayer>();
    auto& header = layer.GetHeader();

    if (!std::find(known_hw.begin(), known_hw.end(), (arp_hardware)header.hwtype.Convert())) {
        std::cerr << "Unknown ARP Hardware Type: " << header.hwtype.Convert() << '\n';
        return;
    }

    if (!std::find(known_proto.begin(), known_proto.end(), (arp_proto)header.protype.Convert())) {
        std::cerr << "Unknown ARP Protocol Type: " << header.protype.Convert() << '\n';
        return;
    }

    auto& arp_body = buffer.GetPayload().as<ARP_IPv4>();

    // Place a mac address - source ip pair into the table
    // This is always relevant
    auto& mapped_value = arp_translation_table[arp_body.src_ip];
    std::copy(std::begin(arp_body.src_mac), std::end(arp_body.src_mac), mapped_value.begin());

    // Check if ARP is for us
    if (arp_body.dest_ip != ip.GetAddress()) {
        return;
    }

    switch (header.opcode) {
    case 0x001: { // Arp Request
        NetworkBuffer response = m_arp_buffer_config.BuildBuffer(sizeof(ARP_IPv4));

        EthernetConnection outgoing_connection = FlipConnection(connection);

        response.GetLayer<LayerType::Ethernet>()->SetupEthConnection(outgoing_connection);

        ARPLayer& arp = *response.GetLayer<LayerType::ARP>();

        arp.SetupARPHeader((arp_hardware)header.hwtype.Convert(), (arp_proto)header.protype.Convert());
        arp.SetARPOpcode(0x002);

        auto& payload = response.GetPayload().as<ARP_IPv4>();
        std::copy(std::begin(arp_body.src_mac), std::end(arp_body.src_mac), payload.dest_mac);
        std::copy(std::begin(mac), std::end(mac), payload.src_mac);

        payload.dest_ip = arp_body.src_ip;
        payload.src_ip = ip.GetAddress();

        SendEthernet(std::move(response), outgoing_connection.destination_mac, ETH_P_ARP);
        break;
    }
    case 0x002: { // ARP Response
        auto it = m_arp_wait_map.find(IPv4Address(arp_body.src_ip));

        if (it != m_arp_wait_map.end()) {
            it->second.set_value();
        }
        break;
    }
    }
}

void NetworkDevice::SendEthernet(NetworkBuffer data, EthernetMAC destination, u16 type)
{
    auto* eth_layer = data.GetLayer<LayerType::Ethernet>();
    if (!eth_layer) {
        return;
    }
    eth_layer->SetDestMac(destination);
    eth_layer->SetSourceMac(mac);
    eth_layer->SetEthernetType(type);

    write(tun_fd, data.Data(), data.Size());
}

// Taken from: https://gist.github.com/fxlv/81209bbd150abfeaceb1f85ff076c9f3
u32 IPv4ChecksumAdd(void* addr, u32 count, u32 start)
{
    // Simply sum all the 16 bit words
    u32 sum = start;
    u8* ptr = (u8*)addr;
    for (int i = 0; i < count; i++) {
        if (i % 2 == 1) {
            // Low byte
            sum += (u32)ptr[i];
        } else {
            // High byte
            sum += (u32)ptr[i] << 8;
        }
    }

    return sum;
}

u16 IPv4ChecksumEnd(u32 csum)
{
    // Take the ones compliment
    while (csum >> 16) {
        csum = (csum & 0xffff) + (csum >> 16);
    }

    return ~csum;
}

u16 IPv4Checksum(void* addr, u32 count)
{
    return IPv4ChecksumEnd(IPv4ChecksumAdd(addr, count));
}
u16 IPv4Buffer::RunIPHeaderChecksum()
{
    return IPv4Checksum(m_buffer.Data() + sizeof(EthernetHeader), GetIPv4Header().header_length * 4);
}
std::optional<NetworkDevice::IPv4Route> NetworkDevice::MakeRoutingDecision(IPv4Address to)
{
    IPv4Address target;
    if (to.ApplySubnetMask(subnet_mask) == ip.ApplySubnetMask(subnet_mask)) {
        target = to;
    } else {
        target = m_router;
    }

    auto result = SendArp(target);
    if (!result) {
        return {};
    }

    return { IPv4Route {
        *result,
        to,
    } };
}
std::optional<NetworkDevice::IPv6Route> NetworkDevice::MakeRoutingDecision(IPv6Address to)
{
    if (to.IsMulticast()) {
        u32 multicast_bits = (to.Get() & std::bitset<128>(0xFFFFFF)).to_ulong();
        EthernetMAC multicast_mac = { 0x33, 0x33, 0xff, (u8)(multicast_bits >> 16), (u8)((multicast_bits >> 8) & 0xff), (u8)(multicast_bits & 0xff) };
        return { IPv6Route {
            multicast_mac,
            to } };
    }

    IPv6Address target;
    if (to.ApplySubnetMask(subnet_mask6) == m_ip6.ApplySubnetMask(subnet_mask6)) {
        target = to;
    } else {
        target = m_router6;
    }

    auto result = icmpv6Manager.SendNDP(target);
    if (!result) {
        return {};
    }

    return { IPv6Route {
        *result,
        to } };
}
void NetworkDevice::ResolveIPv4(NetworkBuffer& buffer, EthernetConnection& eth_connection)
{
    auto& ipv4 = buffer.AddLayer<LayerType::IPv4>(5 * 4);
    auto& header = ipv4.GetHeader();

    if (header.version != 4) {
        buffer.Hexdump();
        std::cerr << "Received IPv4 Packet without version set to 4. Version is: " << (u16)header.version << " Dropping\n";
        return;
    }

    if (header.header_length < 5) {
        std::cerr << "Received IPv4 packet with header length less than 5. Header Length is: " << header.header_length << " Dropping\n";
        return;
    } else if (header.header_length > 5) {
        buffer.ResizeTop(header.header_length * 4);
    }

    if (header.time_to_live == 0) {
        std::cerr << "Received IPv4 packet with 0 TTL, Dropping\n";
        return;
    }

    if (IPv4Checksum(&header, header.header_length * 4) != 0) {
        std::cerr << "Received Corrupted IPv4 Packet, Dropping\n";
        return;
    }

    if (header.IsFragment()) {
        std::scoped_lock lock(m_fragment_mutex);

        auto frag_it = m_ip_fragments.find(PacketFragmentID { header.id, { IPv4Address(header.source_ip) } });

        if (frag_it == m_ip_fragments.end()) {
            PacketFragmentID id { header.id, { IPv4Address(header.source_ip) } };

            fragment_timeout_queue.emplace_back(std::chrono::steady_clock::now() + fragment_timeout_time, id);
            m_fragment_timeout_cv.notify_one();
            auto [new_it, inserted] = m_ip_fragments.emplace(id, std::make_unique<IPv4Fragments>(--fragment_timeout_queue.end()));
            frag_it = new_it;
        }

        IPv4Fragments* fragments = nullptr;
        if (!(fragments = dynamic_cast<IPv4Fragments*>(frag_it->second.get()))) {
            // The fragments are for IPv6
            return;
        }

        fragments->AddFragment(std::move(buffer), !(header.GetFlags() & IPv4Header::MoreFragments), header.GetFragmentOffset());

        if (header.GetFragmentOffset() == 0) {
            fragments->CopyInHeader(header);
        }

        if (!fragments->IsFull()) {
            return;
        }

        NetworkBuffer new_buffer = fragments->Release();
        fragment_timeout_queue.erase(fragments->GetQueueIt());
        m_ip_fragments.erase(frag_it);

        new_buffer.ResetLayers();

        ResolveIPv4(new_buffer, eth_connection);
        return;
    }

    IPv4Connection connection {
        eth_connection,
        IPv4Address(header.source_ip),
        ip,
        header.id,
        header.type_of_service,
    };

    switch (header.protocol) {
    case IPv4Header::ICMP:
#ifdef DEBUG_TRACE_PACKETS
        std::cout << "Resolving ICMP" << std::endl;
#endif
        icmpManager.HandleIncoming(std::move(buffer), connection);
        break;
    case IPv4Header::UDP:
#ifdef DEBUG_TRACE_PACKETS
        std::cout << "Resolving UDP" << std::endl;
#endif
        udpManager.HandleIncoming(std::move(buffer), connection);
        break;
    case IPv4Header::TCP:
        tcpManager.HandleIncoming(std::move(buffer), connection.ToNetworkConnection());
        break;
    default:
        break;
    }
}

void NetworkDevice::SendIPv4(NetworkBuffer buffer, IPv4Address target, IPv4Header::ProtocolType proto_type)
{
    auto* ipv4layer = buffer.GetLayer<LayerType::IPv4>();
    if (!ipv4layer) {
        return;
    }
    buffer.RemoveLayersAbove(ipv4layer);

    // MakeRoutingDecision can block in this case. This is bad in the listen thread as we cannot block
    // for any reason, so dispatch the call to another thread
    if (std::this_thread::get_id() == listen_thread.get_id() && !arp_translation_table.contains(target.GetAddress())) {
        // This is wasteful and dangerous, as the thread cannot be reliably destroyed before the program
        // ends. But, this case is incredibly rare (we have a hit on this when we get a packet from an IP
        // address, but we don't know the MAC address while in the listen thread). The only known case of
        // this being triggered is the start of an incoming TCP connection. This means it's passable.
        auto th = std::thread([moved_buffer = std::move(buffer), target, proto_type, this]() mutable { SendIPv4(std::move(moved_buffer), target, proto_type); });
        th.detach();
        return;
    }

    auto maybe_route = MakeRoutingDecision(target);
    if (!maybe_route.has_value()) {
        // Could not figure out which MAC address to send our packet to
        return;
    }

    IPv4Layer::Config config {};
    config.src_ip = ip;
    config.dest_ip = maybe_route->dest_addr;
    config.proto = proto_type;

    if (buffer.Size() > MTU + sizeof(EthernetHeader)) {
        u16 fragment_offset = 0;
        // Compute fragment size
        u16 frag_size = (MTU - ipv4layer->GetHeader().header_length * 4) / 8;

        // Use same id for all fragments
        u16 id = rand();

        // Fixme: final frame perfect match with MTU
        //        Also final frame has to be > 8 bytes
        while (buffer.Size() - fragment_offset > MTU + sizeof(EthernetHeader) - sizeof(IPv4Header)) {
            // Make a new buffer
            // IPv4Buffer frag_ipv4 = IPv4Buffer::WithSize(frag_size * 8);
            NetworkBuffer frag_buffer = NetworkBuffer::WithSize(sizeof(EthernetHeader) + sizeof(IPv4Header) + frag_size * 8);
            frag_buffer.CopyLayout(buffer);
            auto* frag_ipv4 = frag_buffer.GetLayer<LayerType::IPv4>();

            config.ConfigureLayer(*frag_ipv4);

            // Set up the new fragment related parts of the header
            frag_ipv4->SetFlags(IPv4Header::MoreFragments);
            frag_ipv4->SetFragmentOffset(fragment_offset / 8);
            frag_ipv4->SetLength(frag_size * 8 + ipv4layer->GetHeader().header_length * 4);
            frag_ipv4->SetID(id);

            // Finally, perform the checksum
            frag_ipv4->ApplyChecksum();

            // Copy in the payload
            memcpy(frag_buffer.GetPayload().Data(), buffer.GetPayload().Data() + fragment_offset, frag_size * 8);

            SendEthernet(std::move(frag_buffer), maybe_route->dest_mac, ETH_P_IP);

            fragment_offset += frag_size * 8;
        }

        // Finally, onto the final fragment
        // The only difference is the no flags, and we use a different frag size (that is not divided by eight)
        frag_size = buffer.GetPayload().Size() - fragment_offset;

        // Exact (almost) same code
        NetworkBuffer frag_buffer = NetworkBuffer::WithSize(sizeof(EthernetHeader) + sizeof(IPv4Header) + frag_size);
        frag_buffer.CopyLayout(buffer);
        auto* frag_ipv4 = frag_buffer.GetLayer<LayerType::IPv4>();
        config.ConfigureLayer(*frag_ipv4);
        frag_ipv4->SetFlags(IPv4Header::NoFlags); // Only Change
        frag_ipv4->SetFragmentOffset(fragment_offset / 8);
        frag_ipv4->SetLength(frag_size + ipv4layer->GetHeader().header_length * 4);
        frag_ipv4->SetID(id);
        frag_ipv4->ApplyChecksum();
        memcpy(frag_buffer.GetPayload().Data(), buffer.GetPayload().Data() + fragment_offset, frag_size);
        SendEthernet(std::move(frag_buffer), maybe_route->dest_mac, ETH_P_IP);
    } else {
        config.ConfigureLayer(*ipv4layer);
        ipv4layer->SetLength(ipv4layer->GetHeader().header_length * 4 + buffer.GetPayload().Size());
        ipv4layer->ApplyChecksum();

        SendEthernet(std::move(buffer), maybe_route->dest_mac, ETH_P_IP);
    }
}

IPv4Buffer NetworkDevice::MakeIPv4Buffer(size_t payload_size)
{
    return IPv4Buffer(VLBuffer::WithSize(sizeof(EthernetHeader) + sizeof(IPv4Header) + payload_size));
}

std::optional<IPv4Connection> NetworkDevice::MakeIPConnection(IPv4Address address)
{
    EthernetMAC router_mac {};

    if (arp_translation_table.contains(address.GetAddress())) {
        router_mac = arp_translation_table[address.GetAddress()];
    } else {
        auto maybe_mac = SendArp(address);
        if (!maybe_mac) {
            std::cerr << "ARP Failed" << std::endl;
            return {};
        }

        router_mac = maybe_mac.value();
    }

    IPv4Connection connection {
        EthernetConnection {
            mac,
            router_mac,
            ETH_P_IP,
        },
        address,
        ip,
        1,
        0,
    };

    return connection;
}

std::optional<EthernetMAC> NetworkDevice::SendArp(IPv4Address target)
{
    using namespace std::chrono_literals;

    if (m_arp_wait_map.contains(target)) {
        return {};
    }

    if (arp_translation_table.contains(target.GetAddress())) {
        return { arp_translation_table[target.GetAddress()] };
    }

    // Fixme: Race condition
    /*m_arp_wait_map[target] = std::promise<void>();
    auto future = m_arp_wait_map[target].get_future();*/

    auto [it, did_insert] = m_arp_wait_map.insert(std::make_pair(target, std::move(std::promise<void>())));
    if (!did_insert) {
        std::cerr << "Did Not Insert" << std::endl;
        return {};
    }
    auto future = it->second.get_future();

    // auto buf = MakeARPBuffer(sizeof(ARP_IPv4));
    EthernetConnection connection {
        .destination_mac = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff },
        .connection_type = ETH_P_ARP,
    };
    auto buf = m_arp_buffer_config.BuildBuffer(sizeof(ARP_IPv4));
    auto* arp = buf.GetLayer<LayerType::ARP>();

    std::copy(mac.begin(), mac.end(), std::begin(connection.source_mac));

    arp->SetupARPHeader(arp_hardware::ethernet, arp_proto::IPv4);
    arp->SetARPOpcode(0x001);

    auto& arp_payload = buf.GetPayload().as<ARP_IPv4>();
    std::copy(mac.begin(), mac.end(), std::begin(arp_payload.src_mac));
    arp_payload.src_ip = ip.GetAddress();
    for (u8& mac_byte : arp_payload.dest_mac) {
        mac_byte = 0;
    }
    arp_payload.dest_ip = target.GetAddress();

    // VLBuffer vlbuf = buf.Release();

    for (int i = 0; i < 5; i++) {
        SendEthernet(buf.Copy(), connection.destination_mac, ETH_P_ARP);

        auto status = future.wait_for(1s);

        m_arp_wait_map.erase(target);

        switch (status) {
        case std::future_status::timeout:
            std::cerr << "Timeout" << std::endl;
        case std::future_status::deferred: // This should not happen
            break;
        case std::future_status::ready:
            return arp_translation_table[target.GetAddress()];
        }
    }

    return {};
}

void NetworkDevice::IPTimeoutFunction(std::stop_token token)
{
    while (!token.stop_requested()) {
        std::unique_lock lock(m_fragment_mutex);

        if (!fragment_timeout_queue.empty()) {
            m_fragment_timeout_cv.wait_until(
                lock,
                fragment_timeout_queue.front().first);
        } else {
            m_fragment_timeout_cv.wait(lock, [this, &token]() { return token.stop_requested() || !fragment_timeout_queue.empty(); });
        }

        if (token.stop_requested()) {
            break;
        }

        auto now = std::chrono::steady_clock::now();
        for (auto it = fragment_timeout_queue.begin(); it != fragment_timeout_queue.end();) {
            if (it->first > now) {
                break;
            }

            m_ip_fragments.erase(it->second);
            it = fragment_timeout_queue.erase(it);
        }
    }
}

EthernetConnection NetworkDevice::FlipConnection(const EthernetConnection& other)
{
    EthernetConnection flipped {
        .connection_type = other.connection_type,
    };

    std::copy(other.source_mac.begin(), other.source_mac.end(), flipped.destination_mac.begin());
    std::copy(mac.begin(), mac.end(), flipped.source_mac.begin());

    return flipped;
}
IPv4Connection NetworkDevice::FlipConnection(const IPv4Connection& other)
{
    IPv4Connection flipped {
        .eth = FlipConnection(other.eth),
        .connected_ip = other.connected_ip,
        .our_ip = other.our_ip,
        .id = other.id,
        .type_of_service = other.type_of_service,
    };

    return flipped;
}
IPv6Connection NetworkDevice::FlipConnection(const IPv6Connection& other)
{
    IPv6Connection flipped {
        .eth = FlipConnection(other.eth),
        .connected_ip = other.connected_ip,
        .our_ip = other.our_ip,
        .flow_label = other.flow_label,
        .traffic_class = other.traffic_class,
    };

    return flipped;
}

void NetworkDevice::ResolveIPv6(NetworkBuffer& buffer, EthernetConnection& connection)
{
    IPv6Layer& ipv6 = buffer.AddLayer<LayerType::IPv6>(sizeof(IPv6Header));
    auto& header = ipv6.GetHeader();

    if (ipv6.GetVersion() != 6) {
        std::cerr << "Received IPv6 Packet without version set to 6: Version is " << ipv6.GetVersion() << ". Dropping" << std::endl;
        return;
    }

    // Is it for us?
    // Two ways, we are the destination, or it matches a multicast for us
    if (!m_ip6.MatchesMulticast(ipv6.GetDestAddr()) && m_ip6 != ipv6.GetDestAddr()) {
        // Not for us, dropping
        return;
    }

    // Parse the next header
    // Consider this to have variable width header size
    // We will resize as necessary
    u8 next_header = header.next_header;
    size_t current_size = sizeof(IPv6Header);
    bool more_options = true;
    for (int i = 0; i < 100 && more_options; i++) { // Avoid getting caught in infinite loop, 100 options seems reasonable enough
        switch (next_header) {
        case IPPROTO_HOPOPTS: {
            // Hop-by-hop options
            auto payload = buffer.GetPayload();
            next_header = payload[0];
            u8 header_length = payload[1];
            current_size += header_length;
            buffer.ResizeTop(current_size);

            // TODO: Implement
            break;
        }
        case IPPROTO_ROUTING: {
            // Routing options for tracking visited nodes
            auto payload = buffer.GetPayload();
            next_header = payload[0];
            u8 header_length = payload[1];
            current_size += header_length;
            buffer.ResizeTop(current_size);

            // TODO: Implement
            break;
        }
        case IPPROTO_FRAGMENT: {
            auto payload = buffer.GetPayload();

            auto& frag_header = payload.as<IPv6FragmentHeader>();
            next_header = frag_header.next_header;
            current_size += sizeof(frag_header);
            buffer.ResizeTop(current_size);

            std::scoped_lock lock (m_fragment_mutex);
            PacketFragmentID id { (int)frag_header.id, { ipv6.GetSourceAddr() } };

            auto it = m_ip_fragments.find(id);
            if (it == m_ip_fragments.end()) {
                fragment_timeout_queue.emplace_back(std::chrono::steady_clock::now() + fragment_timeout_time, id);
                m_fragment_timeout_cv.notify_one();

                auto [new_it, inserted] = m_ip_fragments.emplace(id, std::make_unique<IPv6Fragments>(--fragment_timeout_queue.end()));
                it = new_it;
            }

            IPv6Fragments* fragments = nullptr;
            if (!(fragments = dynamic_cast<IPv6Fragments*>(it->second.get()))) {
                // The fragments are for IPv4
                return;
            }

            fragments->AddFragment(std::move(buffer), frag_header.GetFlags() != 1, frag_header.GetFragmentOffset());

            if (frag_header.GetFragmentOffset() == 0) {
                fragments->CopyInHeader(header, current_size);
            }

            if (!fragments->IsFull()) {
                return;
            }

            NetworkBuffer new_buffer = fragments->Release();
            fragment_timeout_queue.erase(fragments->GetQueueIt());
            m_ip_fragments.erase(it);

            new_buffer.ResetLayers();

            ResolveIPv6(new_buffer, connection);
            return;
        }
        case IPPROTO_DSTOPTS: {
            // Routing options for tracking visited nodes
            auto payload = buffer.GetPayload();
            next_header = payload[0];
            u8 header_length = payload[1];
            current_size += header_length;
            buffer.ResizeTop(current_size);

            // TODO: Implement
            break;
        }
        case IPPROTO_NONE:
            // Drop the packet
            return;
        case IPPROTO_ENCAP:
        case IPPROTO_AH: // Authentication
            std::cerr << "Received IPv6 Packet with Unsupported Option: " << (u16)next_header << ". Dropping" << std::endl;
            return;
        default:
            // This means that the protocol is likely not an extension header (it will be caught as unsupported otherwise)
            more_options = false;
            break;
        }
    }

    IPv6Connection ip_connection = {
        .eth = connection,
        .connected_ip = (IPv6Address)header.source_ip,
        .our_ip = (IPv6Address)header.dest_ip,
        .flow_label = ipv6.GetFlowLabel(),
        .traffic_class = (u8)ipv6.GetTrafficClass(),
    };

    switch (next_header) {
    case IPv6Header::TCP:
#ifdef DEBUG_TRACE_PACKETS
        std::cout << "Resolving TCP" << std::endl;
#endif
        tcpManager.HandleIncoming(std::move(buffer), ip_connection.ToNetworkConnection());
        break;
    case IPv6Header::UDP:
        std::cerr << "Received IPv6 to unsupported UDP" << std::endl;
        break;
    case IPv6Header::ICMPv6:
#ifdef DEBUG_TRACE_PACKETS
        std::cout << "Resolving ICMPv6" << std::endl;
#endif
        icmpv6Manager.HandleIncoming(std::move(buffer), ip_connection);
        break;
    default:
        std::cerr << "Received IPv6 Packet with Unsupported Protocol: " << (u16)next_header << ". Dropping" << std::endl;
        break;
    }
}
void NetworkDevice::SendIPv6(NetworkBuffer data, IPv6Address target, IPv6Header::ProtocolType protocol)
{
    IPv6Layer* layer = data.GetLayer<LayerType::IPv6>();
    if (!layer) {
        std::cerr << "SendIPv6 Received Malformed Buffer" << std::endl;
        return;
    }

    // Same logic as SendIPv4
    // MakeRoutingDecision can block in this case. This is bad in the listen thread as we cannot block
    // for any reason, so dispatch the call to another thread
    if (std::this_thread::get_id() == listen_thread.get_id() && !icmpv6Manager.m_ndp_map.contains(target)) {
        // This is wasteful and dangerous, as the thread cannot be reliably destroyed before the program
        // ends. But, this case is incredibly rare (we have a hit on this when we get a packet from an IP
        // address, but we don't know the MAC address while in the listen thread). The only known case of
        // this being triggered is the start of an incoming TCP connection. This means it's passable.
        auto th = std::thread([moved_buffer = std::move(data), target, protocol, this]() mutable { SendIPv6(std::move(moved_buffer), target, protocol); });
        th.detach();
        return;
    }

    std::optional<IPv6Route> maybe_route = MakeRoutingDecision(target);

    if (!maybe_route) {
        return;
    }

    if (data.Size() > MTU + sizeof(EthernetHeader)) {
        // Before we get started, the payload is now everything above ip6
        data.RemoveLayersAbove(layer);

        // Technically we are supposed to split options somewhere here into per-fragment and others
        // But, we are not really handling options at all, so this distinction is not useful to us

        IPv6Layer::Config cfg {};
        cfg.src_ip = m_ip6;
        cfg.dest_ip = maybe_route->dest_addr;
        cfg.protocol = protocol;
        cfg.options = { IPv6Layer::IPv6Option::Fragment };

        NetworkBufferConfig frag_cfg = m_default_l1_config.Copy();
        frag_cfg.AddLayer<LayerType::IPv6>(cfg);

        u16 fragment_offset = 0;
        u16 frag_size = (MTU - cfg.LayerSize()) / 8;
        u32 id = rand();


        while (data.Size() - fragment_offset > MTU + sizeof(EthernetHeader) - cfg.LayerSize()) {
            NetworkBuffer frag_buffer = frag_cfg.BuildBuffer(frag_size * 8);
            auto* frag_ipv6 = frag_buffer.GetLayer<LayerType::IPv6>();

            // We cannot quite configure the fragment header in the layer type
            auto maybe_option = frag_ipv6->GetOption(IPv6Layer::IPv6Option::Fragment);
            if (!maybe_option) {
                // Then we don't have a frag header, this is a fail-case
                std::cerr << "Failed to make valid fragment header for IPv6" << std::endl;
                return;
            }

            auto& frag_header = maybe_option->as<IPv6FragmentHeader>();
            frag_header.SetFlags(1);
            frag_header.SetFragmentOffset(fragment_offset / 8);
            frag_header.id = id;

            memcpy(frag_buffer.GetPayload().Data(), data.GetPayload().Data() + fragment_offset, frag_size * 8);

            SendEthernet(std::move(frag_buffer), maybe_route->dest_mac, ETH_P_IPV6);

            fragment_offset += frag_size * 8;
        }

        // Calculate final fragment size
        frag_size = data.GetPayload().Size() - fragment_offset;

        // Exact same code
        NetworkBuffer frag_buffer = frag_cfg.BuildBuffer(frag_size);
        auto* frag_ipv6 = frag_buffer.GetLayer<LayerType::IPv6>();
        auto maybe_option = frag_ipv6->GetOption(IPv6Layer::IPv6Option::Fragment);
        if (!maybe_option) {
            std::cerr << "Failed to make valid fragment header for IPv6" << std::endl;
            return;
        }
        auto& frag_header = maybe_option->as<IPv6FragmentHeader>();
        frag_header.SetFlags(0); // Only difference
        frag_header.SetFragmentOffset(fragment_offset / 8);
        frag_header.id = id;
        memcpy(frag_buffer.GetPayload().Data(), data.GetPayload().Data() + fragment_offset, frag_size);
        SendEthernet(std::move(frag_buffer), maybe_route->dest_mac, ETH_P_IPV6);
    } else {
        layer->SetSourceAddr((NetworkIPv6Address)m_ip6);
        layer->SetDestAddr((NetworkIPv6Address)maybe_route->dest_addr);
        layer->SetProtocol(protocol);

        SendEthernet(std::move(data), maybe_route->dest_mac, ETH_P_IPV6);
    }
}
