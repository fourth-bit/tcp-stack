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
    std::cout << index << '\n';

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

bool IPv4Fragments::AddFragment(NetworkBuffer data)
{
    // From RFC 815
    auto payload = data.GetPayload();
    auto* ipv4_ptr = data.GetLayer<LayerType::IPv4>();
    if (!ipv4_ptr) {
        return false;
    }

    IPv4Header& data_header = ipv4_ptr->GetHeader();
    u16 offset = data_header.GetFragmentOffset() * 8;
    bool last_frag = !(data_header.GetFlags() & IPv4Header::MoreFragments);

    if (offset == 0) {
        CopyInHeader(data_header);
    }

    for (auto it = HoleDescriptor.begin(); it != HoleDescriptor.end(); ++it) {
        auto& hole = *it;
        if (offset > hole.fragment_last || offset + payload.Size() < hole.fragment_first) {
            // There has to be an optimization here
            continue;
        }

        if (hole.fragment_last > offset + data.Size() && !last_frag) {
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
bool IPv4Fragments::IsFull() const
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

NetworkDevice::NetworkDevice(EthernetMAC mac_address,
    IPv4Address ip_addr,
    u8 subnet,
    IPv4Address router,
    size_t mtu)
    : mac(mac_address)
    , m_router(router)
    , icmpManager(this)
    , udpManager(this)
    , tcpManager(this)
    , MTU(mtu)
    , m_arp_buffer_config()
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
    std::cout << ip << std::endl;
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

    // Setup A Wakeup for the fragment timeout and listen functions for the
    // (eventual) destructor

    int fds[2];
    pipe(fds);

    m_thread_notify_fd = fds[1];
    m_thread_wakeup_fd = fds[0];

    listen_thread = std::thread([this]() { Listen(); });
    fragment_timeout = std::jthread([this](std::stop_token token) { IPTimeoutFunction(token); });
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
        if ((!header.dest_mac.IsBroadcast() && header.dest_mac != mac) || header.src_mac == mac) {
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
u32 IPv4ChecksumAdd(void* addr, int count, u32 start)
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

u16 IPv4Checksum(void* addr, int count)
{
    return IPv4ChecksumEnd(IPv4ChecksumAdd(addr, count));
}
u16 IPv4Buffer::RunIPHeaderChecksum()
{
    return IPv4Checksum(m_buffer.Data() + sizeof(EthernetHeader), GetIPv4Header().header_length * 4);
}
std::optional<NetworkDevice::Route> NetworkDevice::MakeRoutingDecision(IPv4Address to)
{
    SubnetMask mask = the_net_dev->GetSubnetMask();
    IPv4Address target;
    if (to.ApplySubnetMask(mask) == the_net_dev->GetIPAddress().ApplySubnetMask(mask)) {
        target = to;
    } else {
        target = the_net_dev->GetGateway();
    }

    auto result = the_net_dev->SendArp(target);
    if (!result) {
        return {};
    }

    return { NetworkDevice::Route {
        *result,
        to,
    } };
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

        auto frag_it = m_ip_fragments.find(IPv4FragmentID { header.id, IPv4Address(header.source_ip) });

        if (frag_it == m_ip_fragments.end()) {
            IPv4FragmentID id { header.id, IPv4Address(header.source_ip) };

            fragment_timeout_queue.emplace_back(std::chrono::steady_clock::now() + fragment_timeout_time, id);
            m_fragment_timeout_cv.notify_one();
            // FIXME: delete pls
            //  auto [new_it, inserted] = m_ip_fragments.insert({ id, IPv4Fragments(header.total_length, --fragment_timeout_queue.end()) });
            auto [new_it, inserted] = m_ip_fragments.emplace(id, IPv4Fragments(header.total_length, --fragment_timeout_queue.end()));
            frag_it = new_it;
        }
        frag_it->second.AddFragment(std::move(buffer));

        if (!frag_it->second.IsFull()) {
            return;
        }

        NetworkBuffer new_buffer = frag_it->second.Release();
        fragment_timeout_queue.erase(frag_it->second.GetQueueIt());
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
        tcpManager.HandleIncoming(std::move(buffer), connection);
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

    auto maybe_route = MakeRoutingDecision(target);
    if (!maybe_route) {
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

        auto status = future.wait_for(100ms);

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
        std::unique_lock lock (m_fragment_mutex);

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
