//
// Created by Ryan Wolk on 6/7/23.
//

#pragma once

struct IPv4Connection;
class NetworkBuffer;

class TCPManager {
public:
    void HandleIncoming(NetworkBuffer, IPv4Connection);
};
