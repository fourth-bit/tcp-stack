#include <arpa/inet.h>
#include <cstring>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>
#include <linux/if.h>
#include <ifaddrs.h>

#include <iostream>
#include <unordered_map>
#include <sstream>
#include <thread>


#include "NetworkDevice.h"
#include "NetworkOrder.h"
#include "TimerManager.h"

std::unique_ptr<NetworkDevice> the_net_dev;

void initialize_net_dev()
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

    // Get IP addresses a little differently, use getifaddrs because
    // ipv6 doesn't work with ioctl
    ifaddrs* ifas;
    if (getifaddrs(&ifas) != 0) {
        perror("getifaddrs");
        return;
    }

    // We don't need the socket anymore
    close(fd);

    IPv4Address ip4_address;
    IPv6Address ip6_address;

    // Traverse it as a linked list
    for (ifaddrs* ifa = ifas; ifa != nullptr; ifa = ifa->ifa_next) {
        // Only look at the eth0 device
        if (strcmp(ifa->ifa_name, "eth0") == 0) {
            int family = ifa->ifa_addr->sa_family;

            if (family == AF_INET) {
                auto* ipaddr = (sockaddr_in*)ifa->ifa_addr;
                auto ip_address = NetworkOrdered<u32>::WithNetworkOrder(ipaddr->sin_addr.s_addr);
                ip4_address = IPv4Address(ip_address);
            } else if (family == AF_INET6) {
                auto* ip6_sockaddr = (sockaddr_in6*)ifa->ifa_addr;
                if (ip6_sockaddr->sin6_scope_id == 0) {
                    auto* ip6_out = &ip6_sockaddr->sin6_addr;
                    auto* ip6_network = reinterpret_cast<NetworkIPv6Address*>(ip6_out);
                    ip6_address = (IPv6Address)*ip6_network;
                }
            }
        }
    }

    freeifaddrs(ifas);


    the_net_dev = std::make_unique<NetworkDevice>(
        mac_address,
        ip4_address,
        16,
        IPv4Address::FromString("172.18.0.1").value(),
        ip6_address);

    std::cout << "IPv4: " << ip4_address << std::endl;
    std::cout << "IPv6: " << ip6_address << std::endl;

    //    for (int i = 0; i < 10; i++) {
    //        auto address = IPv4Address::FromString("172.18.0.7");
    //        auto maybe_us = the_net_dev->GetICMPManager().SendEchoRequest(*address);
    //        if (maybe_us) {
    //            std::cout << "Ping (" << i << ") back in " << maybe_us->count() << "us" << std::endl;
    //        } else {
    //            std::cout << "Ping (" << i << ") failed" << std::endl;
    //        }
    //    }
}

void run_tcp_connection(NetworkAddress target, u16 port)
{
    std::unique_ptr<TCPSocket> sock(dynamic_cast<TCPSocket*>(Socket::Create(PROTOCOL::INTERNET, SOCK_TYPE::STREAM)));

    sock->Connect(target, port);

    std::stringstream ss;
    ss << "Hello " << target << ":" << port << "\n";
    std::string data = ss.str();

    // Place message in VLBuffer
    VLBuffer payload = VLBuffer::WithSize(data.size());
    std::copy(data.begin(), data.end(), payload.Data());

    u64 written = 0;
    do {
        written += sock->Write(payload.AsView().SubBuffer(written));
    } while (written != payload.Size());

    auto maybe_read_error = sock->Read();
    if (maybe_read_error.IsError()) {
        auto* error = dynamic_cast<SocketError*>(maybe_read_error.GetError());
        if (error->code == SocketError::Code::ConnectionClosing) {
            sock->Close();
            return;
        }

        std::cerr << "Could not read from subsocket. Code: " << (int)error->code << std::endl;
        return;
    }
    auto& buffer = maybe_read_error.GetResult();

    for (size_t i = 0; i < buffer.Size(); i++) {
        std::cout << buffer[i];
    }
    if (buffer.Size() && buffer[buffer.Size() - 1] != '\n') {
        std::cout << std::endl;
    } else {
        std::cout << std::flush;
    }

    sock->Close();
}

void run_tcp_echo_server(u16 incoming_port)
{
    std::unique_ptr<TCPSocket> sock(dynamic_cast<TCPSocket*>(Socket::Create(PROTOCOL::INTERNET6, SOCK_TYPE::STREAM)));
    sock->Bind(incoming_port);

    sock->Listen();

    auto maybe_error = sock->Accept();
    if (maybe_error.IsError()) {
        auto* error = dynamic_cast<SocketError*>(maybe_error.GetError());
        std::cerr << "Could not accept from socket. Code: " << (int)error->code << std::endl;

        return;
    }

    auto result = maybe_error.GetResult();

    auto subsocket = std::unique_ptr<Socket>(result.first);
    auto info = std::unique_ptr<SocketInfo>(result.second);

    for (;;) {
        auto maybe_read_error = subsocket->Read();
        if (maybe_read_error.IsError()) {
            auto* error = dynamic_cast<SocketError*>(maybe_read_error.GetError());
            if (error->code == SocketError::Code::ConnectionClosing) {
                // We will close when the remote closes
                break;
            }

            std::cerr << "Could not read from subsocket. Code: " << (int)error->code << std::endl;
            return;
        }
        auto& buffer = maybe_read_error.GetResult();

        auto* info_raw = dynamic_cast<PortSocketInfo*>(info.get());
        if (info_raw == nullptr) {
            std::cerr << "Unexpected Socket Info Type" << std::endl;
            return;
        }

        auto [network_addr, port] = *info_raw;

        std::cout << network_addr << ": ";
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

    subsocket->Close();
    sock->Close();
}

void run_udp_echo_server(u16 port)
{
    std::unique_ptr<UDPSocket> socket (dynamic_cast<UDPSocket*>(Socket::Create(PROTOCOL::INTERNET6, SOCK_TYPE::DATAGRAM)));
    socket->Bind(port);

    for (;;) {
        auto maybe_read = socket->ReadFrom();
        if (maybe_read.IsError()) {
            auto* error = dynamic_cast<SocketError*>(maybe_read.GetError());
            std::cerr << "Could not read from UDP socket. Code: " << (int)error->code << std::endl;
            return;
        }

        auto& info = maybe_read.GetResult();

        if (info.buffer[0] == 'E' && info.buffer[1] == 'N' && info.buffer[2] == 'D') {
            break;
        }

        std::cout << info.addr << ": ";
        for (size_t i = 0; i < info.buffer.Size(); i++) {
            std::cout << info.buffer[i];
        }
        if (info.buffer.Size() && info.buffer[info.buffer.Size() - 1] != '\n') {
            std::cout << std::endl;
        } else {
            std::cout << std::flush;
        }

        socket->WriteTo(info.buffer.AsView(), info.addr, info.port);
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
        buffer_to_write[x - 'a'] = x;
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

#elif 0
    using namespace std::chrono_literals;

    TimerManager manager;

    manager.AddTimer(20ms, []() {
        std::cout << "Timer 1 Fired" << std::endl;
    });
    manager.AddTimer(200ms, []() {
        std::cout << "Timer 2 Fired" << std::endl;
    });
    manager.AddTimer(2ms, []() {
        std::cout << "Timer 3 Fired" << std::endl;
    });

    std::this_thread::sleep_for(1s);

#elif 0
    ifaddrs* ifas;
    if (getifaddrs(&ifas) != 0) {
        perror("getifaddrs");
        return 1;
    }

    // Traverse it as a linked list
    for (ifaddrs* ifa = ifas; ifa != nullptr; ifa = ifa->ifa_next) {
        // Only look at the eth0 device
        if (strcmp(ifa->ifa_name, "eth0") == 0) {
            int family = ifa->ifa_addr->sa_family;

            if (family == AF_INET) {
                auto* ipaddr = (sockaddr_in*)ifa->ifa_addr;
                auto ip_address = NetworkOrdered<u32>::WithNetworkOrder(ipaddr->sin_addr.s_addr);
                auto ip4 = IPv4Address(ip_address);
                std::cout << "IPv4: " << ip4 << std::endl;
            } else if (family == AF_INET6) {
                auto* ip6_sockaddr = (sockaddr_in6*)ifa->ifa_addr;
                if (ip6_sockaddr->sin6_scope_id == 0) {
                    auto* ip6_out = &ip6_sockaddr->sin6_addr;
                    auto* ip6_network = reinterpret_cast<NetworkIPv6Address*>(ip6_out);
                    IPv6Address ip6(*ip6_network);
                    std::cout << "IPv6: " << ip6 << std::endl;
                }
            }
        }
    }

    freeifaddrs(ifas);

    return 0;
#else
    initialize_net_dev();

//    ICMPv6Manager& icmp = the_net_dev->GetICMPv6Manager();
//    std::optional<EthernetMAC> maybe_mac = icmp.SendNDP(IPv6Address(0xfde8'506e'c3a4'0000, 0x0000'0000'0000'0002));
//    if (maybe_mac) {
//        std::cout << "MAC: " << *maybe_mac << std::endl;
//    } else {
//        std::cout << "NDP Failed" << std::endl;
//    }

    run_udp_echo_server(1000);
    // run_tcp_echo_server(1000);
    // run_tcp_connection({ IPv4Address::FromString("172.18.0.3").value() }, 1000);

    // Give the program time to clean up
    std::this_thread::sleep_for(std::chrono::seconds(5));

    return 0;
#endif
}
