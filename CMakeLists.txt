cmake_minimum_required(VERSION 3.18)
project(TCP)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wno-switch -Wno-reorder -O0")

add_executable(TCP
        NetworkDevice.cpp
        ICMPManager.cpp
        IPv4Address.cpp
        Protocols.cpp
        main.cpp
        FixedTimer.cpp
        UDPManager.cpp
        Socket.cpp
        EthernetMAC.cpp
        NetworkStack.cpp
        NetworkBuffer.cpp
        TCPManager.cpp
        CircularBuffer.cpp
        FIFOLock.cpp
        TimerManager.cpp
        IPv6Address.cpp
        ICMPv6Manager.cpp)