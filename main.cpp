#include <arpa/inet.h>
#include <cstring>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include <iostream>
#include <unordered_map>
#include <sstream>

#include <linux/if.h>
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
    std::unique_ptr<TCPSocket> sock(dynamic_cast<TCPSocket*>(Socket::Create(PROTOCOL::INTERNET, SOCK_TYPE::STREAM)));
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

    subsocket->Close();
    sock->Close();
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

#else
    initialize_net_dev();

    // run_tcp_echo_server(1000);
    run_tcp_connection({ IPv4Address::FromString("172.18.0.2").value() }, 1000);

    // Give the program time to clean up
    std::this_thread::sleep_for(std::chrono::seconds(10));

    return 0;
#endif
}
