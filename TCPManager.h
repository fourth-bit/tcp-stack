//
// Created by Ryan Wolk on 6/7/23.
//

#pragma once

#include "IntDefs.h"
#include "NetworkAddress.h"
#include "NetworkBuffer.h"
#include "Socket.h"
#include "TimerManager.h"
#include "Utils.h"
#include <unordered_map>
#include <unordered_set>

struct IPv4Connection;
class NetworkBuffer;
class NetworkDevice;
struct TCPHeader;

#define DEBUG_TCP

struct TCPConnection {
    NetworkAddress connected_addr;
    u16 connected_port;
    u16 local_port;

    bool operator==(const TCPConnection& other) const
    {
        return (connected_addr == other.connected_addr) && (connected_port == other.connected_port) && (local_port == other.local_port);
    }
};

struct TCPConnectionHasher {
    size_t operator()(const TCPConnection& connection) const
    {
        size_t hash = NetworkAddressHasher {}(connection.connected_addr);
        hash = hash_combine(hash, std::hash<u16> {}(connection.connected_port));
        hash = hash_combine(hash, std::hash<u16> {}(connection.local_port));
        return hash;
    }
};

class TCPManager {
    static const u16 ephemeral_floor = 0xC000;
    static const u16 ephemeral_ceil = 0xFFFF;
    static_assert(ephemeral_floor < ephemeral_ceil);

public:
    explicit TCPManager(NetworkDevice* net_dev)
        : m_net_dev(net_dev)
    {
    }

    void HandleIncoming(NetworkBuffer, IPv4Connection);
    static void DumpPacket(NetworkBuffer&, const TCPConnection&);

    // Called during bind to reserve a port
    bool ReservePort(TCPSocket*, u16 port);
    // Called during connect when there is not a port already chosen, so
    // one is selected automatically
    std::optional<u16> ReserveEphemeral(TCPSocket*);
    // Used to notify the manager that the socket is listening on connections.
    bool RegisterListening(TCPSocket*);
    bool RegisterConnection(TCPSocket*, TCPConnection);
    // Used to notify manager that a listening socket has created a connection
    bool AlertOpenConnection(TCPSocket* listening_socket, TCPSocket* new_socket, TCPConnection);
    bool Unregister(TCPSocket*);

    void SendPacket(NetworkBuffer, NetworkAddress);

    TimerManager& GetRetransmissionTimers() { return m_retransmission_queue; };

private:
    NetworkDevice* m_net_dev;

    // Needs to hold objects for each connection (ip/port --> local port)
    // These are the TCBs, the transmission control blocks
    std::unordered_map<TCPConnection, TCPSocket*, TCPConnectionHasher> m_open_connections {};

    // Needs to be aware of listener sockets for new connections
    std::unordered_map<u16, TCPSocket*> m_listening_ports {};

    // Map of currently used ports, used to quickly figure out ownership when there
    // are no connections
    std::unordered_map<u16, TCPSocket*> m_ports_in_use {};

    // Set of registered sockets: Means sockets that are in m_listening_ports
    // or in m_open_connections
    std::unordered_set<TCPSocket*> m_registered_sockets {};

    TimerManager m_retransmission_queue;

    u16 current_ephemeral { ephemeral_floor };
};
