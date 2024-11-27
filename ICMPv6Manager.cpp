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
    m_config.AddLayer<LayerType::Ethernet>();
    m_config.AddLayer<LayerType::IPv6>();
    m_config.AddLayer<LayerType::ICMPv6>();
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

        auto resp_buf = m_net_dev->FlipConnection(connection).BuildBufferWith(m_config, sizeof(ICMPv6Echo) + size);
        // Finish filling out the headers
        ICMPv6Layer* icmp6_layer = resp_buf.GetLayer<LayerType::ICMPv6>();
        IPv6Layer* ipv6_layer = resp_buf.GetLayer<LayerType::IPv6>();
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

        ipv6_layer->SetSourceAddr((NetworkIPv6Address)m_net_dev->GetIPv6Address());
        ipv6_layer->SetDestAddr((NetworkIPv6Address)connection.connected_ip);
        ipv6_layer->SetProtocol(IPv6Header::ICMPv6);
        ipv6_layer->SetFlowLabel(0);

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
        auto resp_buf = m_net_dev->FlipConnection(connection).BuildBufferWith(m_config,
            sizeof(ICMPv6NetworkAdvertisement) +
                sizeof(ICMPv6NetworkAdvertisement::Option) +
                sizeof(EthernetMAC));

        ICMPv6Layer* icmp6_layer = resp_buf.GetLayer<LayerType::ICMPv6>();
        IPv6Layer* ipv6_layer = resp_buf.GetLayer<LayerType::IPv6>();

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

        ipv6_layer->SetSourceAddr((NetworkIPv6Address)m_net_dev->GetIPv6Address());
        ipv6_layer->SetDestAddr((NetworkIPv6Address)connection.connected_ip);
        ipv6_layer->SetProtocol(IPv6Header::ICMPv6);
        ipv6_layer->SetFlowLabel(0);

        icmp6_layer->ApplyICMPv6Checksum();
        std::cout << icmp6_layer->RunICMPv6Checksum() << std::endl;

        m_net_dev->SendIPv6(std::move(resp_buf), connection.connected_ip, IPv6Header::ICMPv6);
        break;
    }
    default:
        break;
    }
}
std::optional<EthernetMAC> ICMPv6Manager::SendNDP(IPv6Address address)
{
    if (m_ndp_map.contains(address)) {
        return { m_ndp_map[address] };
    }

    return {};
}
