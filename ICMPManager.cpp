//
// Created by Ryan Wolk on 3/27/22.
//

#include <cstring>
#include <iostream>

#include "ICMPManager.h"
#include "NetworkDevice.h"

ICMPManager::ICMPManager(NetworkDevice* dev)
    : m_net_dev(dev)
    , m_config()
{
    // These won't be filled in because defaults do not make sense
    // The current system of setting up connections works fine
    m_config.AddLayer<LayerType::Ethernet>();
    m_config.AddLayer<LayerType::IPv4>();
    m_config.AddLayer<LayerType::ICMP>();
}

void ICMPManager::HandleIncoming(NetworkBuffer buffer, IPv4Connection connection)
{
    auto& icmp = buffer.AddLayer<LayerType::ICMP>(sizeof(ICMPv4Header));
    auto& header = icmp.GetHeader();

    // Todo: Checksum

    switch (header.type) {
    case ICMPv4Header::EchoReq: {
#ifdef DEBUG_TRACE_PACKETS
        std::cout << "Resolving ECHO" << std::endl;
#endif
        size_t data_size = buffer.GetPayload().Size() - sizeof(ICMPv4Echo);

        auto& echo_req = buffer.GetPayload<ICMPv4Echo>();

        //        auto resp_buf = m_config.BuildBuffer(sizeof(ICMPv4Echo) + data_size);
        //        resp_buf.GetLayer<LayerType::IPv4>()->SetupConnection(m_net_dev->FlipConnection(connection));
        auto resp_buf = m_net_dev->FlipConnection(connection).BuildBufferWith(m_config, sizeof(ICMPv4Echo) + data_size);

        ICMPLayer* resp_icmp = resp_buf.GetLayer<LayerType::ICMP>();
        if (!resp_icmp) {
            return; /* Fixme: Add logging */
        }

        auto& resp_header = resp_icmp->GetHeader();
        resp_header.type = ICMPv4Header::EchoResp;
        resp_header.code = header.code;
        // Run later
        resp_header.checksum = 0;

        auto& echo_resp = resp_buf.GetPayload<ICMPv4Echo>();
        echo_resp.id = echo_req.id;
        echo_resp.seq = echo_req.seq;

        memcpy(echo_resp.data, echo_req.data, data_size);

        resp_icmp->ApplyICMPv4Checksum(sizeof(ICMPv4Echo) + data_size);

        m_net_dev->SendIPv4(std::move(resp_buf), connection.connected_ip, IPv4Header::ICMP);
        break;
    }
    case ICMPv4Header::EchoResp: {
        auto& echo_resp = buffer.GetPayload<ICMPv4Echo>();

        auto it = m_connection_map.find(echo_resp.id);
        if (it != m_connection_map.end()) {
            it->second.set_value();
        }
        break;
    }
    }
}
std::optional<std::chrono::microseconds> ICMPManager::SendEchoRequest(IPv4Address address)
{
    using namespace std::chrono_literals;

    int tid = gettid();

    auto [it, did_insert] = m_connection_map.insert({ tid, std::move(std::promise<void>()) });
    if (!did_insert) {
        std::cerr << "could not insert" << std::endl;
        return {};
    }

    auto future = it->second.get_future();

    auto maybe_connection = m_net_dev->MakeIPConnection(address);

    if (!maybe_connection) {
        std::cerr << "could not make ip connection" << std::endl;
        return {};
    }

    IPv4Connection& connection = *maybe_connection;

    // Get a 64 byte payload
    auto buffer = connection.BuildBufferWith(m_config, sizeof(ICMPv4Echo) + 64);
    ICMPLayer* icmp = buffer.GetLayer<LayerType::ICMP>();
    if (!icmp) {
        std::cerr << "Build buffer failed" << std::endl;
        return {};
    }

    ICMPv4Header& header = icmp->GetHeader();
    header.type = ICMPv4Header::EchoReq;
    header.code = 0;

    auto& req = buffer.GetPayload().as<ICMPv4Echo>();
    req.id = tid;
    req.seq = 0;

    auto view = buffer.GetPayload();
    for (size_t i = sizeof(ICMPv4Header); i < view.Size(); i++) {
        view[i] = (u8)i + (u8)0x10;
    }

    // Do the checksum last
    icmp->ApplyICMPv4Checksum(sizeof(ICMPv4Echo) + 64);

    m_net_dev->SendIPv4(std::move(buffer), address, IPv4Header::ICMP);

    auto start = std::chrono::system_clock::now();
    auto status = future.wait_for(1000s);
    auto time_passed = std::chrono::system_clock::now() - start;
    m_connection_map.erase(it);

    auto time_in_ms = std::chrono::duration_cast<std::chrono::microseconds>(time_passed);

    switch (status) {
    case std::future_status::ready:
        return time_in_ms;
    case std::future_status::timeout:
    case std::future_status::deferred:
    default:
        return {};
    }
}
