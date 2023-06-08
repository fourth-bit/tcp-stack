cmake_minimum_required(VERSION 3.18)
project(TCP)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wno-switch -Wno-reorder")

add_executable(TCP
        TCP.cpp
        #TCP.h
        #NetworkOrder.h
        NetworkDevice.cpp
        NetworkDevice.h
        #VLBuffer.h
        #Protocols.h
        ICMPManager.cpp
        #ICMPManager.h
        IPv4Address.cpp
        #IPv4Address.h
        Protocols.cpp
        main.cpp FixedTimer.cpp FixedTimer.h UDPManager.cpp UDPManager.h IntDefs.h Socket.cpp Socket.h EthernetMAC.cpp EthernetMAC.h NetworkStack.cpp NetworkStack.h NetworkBuffer.cpp NetworkBuffer.h Badge.h)
