//
// Created by Ryan Wolk on 11/25/24.
//

#include <cstring>

#include "ICMPv6Manager.h"
#include "NetworkDevice.h"

ICMPv6Manager::ICMPv6Manager(NetworkDevice* dev)
    : m_net_dev(dev)
    , m_config()
{
    m_config = dev->GetIPv6Config().Copy();
    if (m_config.HasLayer<LayerType::IPv6>()) {
        IPv6Layer::Config* ip6_config = m_config.LayerAsRef<LayerType::IPv6>();
        ip6_config->protocol = IPPROTO_ICMPV6;
    }
    m_config.AddLayer<LayerType::ICMPv6>(ICMPv6Layer::Config {});
}

void ICMPv6Manager::HandleIncoming(NetworkBuffer buffer, IPv6Connection connection)
{
    auto& icmp = buffer.AddLayer<LayerType::ICMPv6>(sizeof(ICMPv6Header));
    auto& header = icmp.GetHeader();

    if (icmp.RunICMPv6Checksum() != 0) {
        std::cerr << "ICMPv6 Checksum Failed" << std::endl;
        return;
    }

    switch (header.type) {
    case ICMPv6Header::EchoRequest: {
        size_t size = buffer.GetPayload().Size();
        auto& echo_req = buffer.GetPayload<ICMPv6Echo>();

        auto resp_buf = m_config.BuildBuffer(sizeof(ICMPv6Echo) + size);
        ICMPv6Layer* icmp6_layer = resp_buf.GetLayer<LayerType::ICMPv6>();
        IPv6Layer* ipv6_layer = resp_buf.GetLayer<LayerType::IPv6>();

        ipv6_layer->SetDestAddr((NetworkIPv6Address)connection.connected_ip);

        // Finish filling out the headers
        if (!icmp6_layer) {
            std::cerr << "Failed to build ICMPv6 Response Buffer to Echo Request" << std::endl;
            return; // Something went wrong that shouldn't have
        }

        icmp6_layer->SetType(ICMPv6Header::EchoReply);
        icmp6_layer->SetCode(icmp.GetCode());

        auto& echo_reply = resp_buf.GetPayload<ICMPv6Echo>();
        echo_reply.id = echo_req.id;
        echo_reply.sequence = echo_req.sequence;

        memcpy(echo_reply.data, echo_req.data, size);

        icmp6_layer->ApplyICMPv6Checksum();

        m_net_dev->SendIPv6(std::move(resp_buf), connection.connected_ip, IPv6Header::ICMPv6);
        break;
    }
    case ICMPv6Header::NeighborSolicitation: {
        size_t size = buffer.GetPayload().Size();
        auto& solicitation = buffer.GetPayload<ICMPv6NetworkSolicitation>();

        if (size > sizeof(ICMPv6NetworkSolicitation)) {
            // This means we have a link-layer address
            auto* option = reinterpret_cast<ICMPv6NetworkSolicitation::Option*>(solicitation.options);
            if (option->type == 1 && option->length == 1) {
                m_ndp_map[connection.connected_ip] = *reinterpret_cast<EthernetMAC*>(option->data);
            }
        }

        // Now we need to figure out if this is meant for us
        if ((IPv6Address)solicitation.target_address != m_net_dev->GetIPv6Address()) {
            break;
        }

        // Now we need to build a response
        auto resp_buf = m_config.BuildBuffer(
            sizeof(ICMPv6NetworkAdvertisement) + sizeof(ICMPv6NetworkAdvertisement::Option) + sizeof(EthernetMAC));

        ICMPv6Layer* icmp6_layer = resp_buf.GetLayer<LayerType::ICMPv6>();
        IPv6Layer* ipv6_layer = resp_buf.GetLayer<LayerType::IPv6>();

        ipv6_layer->SetDestAddr((NetworkIPv6Address)connection.connected_ip);

        if (!icmp6_layer) {
            std::cerr << "Failed to build ICMPv6 Response Buffer to Network Solicitation Request" << std::endl;
            return; // Something went wrong that shouldn't have
        }

        icmp6_layer->SetType(ICMPv6Header::NeighborAdvertisement);
        icmp6_layer->SetCode(icmp.GetCode());

        auto& advertisement = resp_buf.GetPayload<ICMPv6NetworkAdvertisement>();
        advertisement._reserved = 0;
        advertisement._reserved2 = 0;
        advertisement._reserved3 = 0;
        advertisement.flags = ICMPv6NetworkAdvertisement::Solicited | ICMPv6NetworkAdvertisement::Override;
        advertisement.target_address = solicitation.target_address;
        auto* option = reinterpret_cast<ICMPv6NetworkAdvertisement::Option*>(advertisement.options);
        option->type = 2;
        option->length = 1; // 8 Bytes
        memcpy(option->data, m_net_dev->GetMac().data(), 6);

        icmp6_layer->ApplyICMPv6Checksum();

        m_net_dev->SendIPv6(std::move(resp_buf), connection.connected_ip, IPv6Header::ICMPv6);
        break;
    }
    case ICMPv6Header::NeighborAdvertisement: {
        size_t size = buffer.GetPayload().Size();
        auto& advertisement = buffer.GetPayload<ICMPv6NetworkAdvertisement>();
        auto ip = (IPv6Address)advertisement.target_address;

        if (size > sizeof(ICMPv6NetworkAdvertisement)) {
            // Then we have the option that we want
            auto* option = reinterpret_cast<ICMPv6NetworkAdvertisement::Option*>(advertisement.options);
            if (option->type == 2 && option->length == 1) {
                m_ndp_map[ip] = *reinterpret_cast<EthernetMAC*>(option->data);

                if (m_ndp_wait_map.contains(ip)) {
                    m_ndp_wait_map[ip].set_value();
                }
            }
        }

        break;
    }
    default:
        break;
    }
}
std::optional<EthernetMAC> ICMPv6Manager::SendNDP(IPv6Address address)
{
    using namespace std::chrono_literals;

    if (m_ndp_wait_map.contains(address)) {
        return {};
    }

    if (m_ndp_map.contains(address)) {
        return { m_ndp_map[address] };
    }

    auto [it, did_insert] = m_ndp_wait_map.insert(std::make_pair(address, std::move(std::promise<void>())));
    if (!did_insert) {
        // This just means out of memory, not much we can do
        return {};
    }
    auto future = it->second.get_future();

    auto resp_buf = m_config.BuildBuffer(
        sizeof(ICMPv6NetworkSolicitation) + sizeof(ICMPv6NetworkSolicitation::Option) + sizeof(EthernetMAC));

    ICMPv6Layer* icmp6_layer = resp_buf.GetLayer<LayerType::ICMPv6>();
    IPv6Layer* ipv6_layer = resp_buf.GetLayer<LayerType::IPv6>();

    if (!icmp6_layer || !ipv6_layer) {
        std::cerr << "Failed to build ICMPv6 Buffer for Network Solicitation Request" << std::endl;
        return {}; // Something went wrong that shouldn't have
    }

    // Make a multicast address to send to
    const SubnetMask6 multicast_subnet (IPv6Address(std::bitset<128>(0xFFFF'FFFF'FFFF'FFFF) << 64 | std::bitset<128>(~(u64)0xFF'FFFF)));
    const IPv6Address multicast_base (0xff02'0000'0000'0000, 0x1'FF00'0000);

    IPv6Address multicast = IPv6Address(multicast_base.Get() | (address.ApplySubnetMask((~multicast_subnet)).Get()));
    ipv6_layer->SetDestAddr((NetworkIPv6Address)multicast);

    icmp6_layer->SetType(ICMPv6Header::NeighborSolicitation);
    icmp6_layer->SetCode(0);

    auto& solicitation = resp_buf.GetPayload<ICMPv6NetworkSolicitation>();
    solicitation.target_address = (NetworkIPv6Address)address;
    auto& option = *reinterpret_cast<ICMPv6NetworkSolicitation::Option*>(solicitation.options);
    option.type = 1;
    option.length = 1;
    memcpy(option.data, m_net_dev->GetMac().data(), 6);

    icmp6_layer->ApplyICMPv6Checksum();

    for (int i = 0; i < 3; i++) {
        m_net_dev->SendIPv6(resp_buf.Copy(), multicast, IPv6Header::ICMPv6);

        auto status = future.wait_for(1s);
        m_ndp_wait_map.erase(address);

        switch (status) {
        case std::future_status::timeout:
            std::cerr << "Timeout" << std::endl;
        case std::future_status::deferred: // This should not happen
            break;
        case std::future_status::ready:
            return m_ndp_map[address];
        }
    }

    return {};
}
