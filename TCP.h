//
// Created by Ryan Wolk on 3/8/22.
//

#pragma once

#include "NetworkDevice.h"
#include "NetworkOrder.h"

struct tcp_header {
    enum connection_flags {
        // Sender reduced rate
        CongestionWindowReduced = 1 << 7,
        // Sender received congestion notification
        ECNEcho = 1 << 6,
        // There is priority data in the thing
        Urgent = 1 << 5,
        ACK = 1 << 4,
        PSH = 1 << 3,
        RST = 1 << 2,
        SYN = 1 << 1,
        FIN = 1,
    };

    NetworkOrdered<u16> source_port;
    NetworkOrdered<u16> dest_port;
    NetworkOrdered<u32> seq_num;
    NetworkOrdered<u32> ack_num;
    u8 _reserved : 4;
    // Header length in 32 bit words
    u8 header_length : 4;
    // See tcp_header::connection_flags
    u8 flags;
    // The amount of bytes a receiver can accept
    NetworkOrdered<u16> window_size;
    u16 checksum;
    // Where the priority data is in the stream
    NetworkOrdered<u16> urgent_pointer;
    u8 data[];
} __attribute__((packed));

class TCPSegment {
public:
    static TCPSegment FromHeader(tcp_header* from_header);

private:
};

class TCP {
public:
    TCP()
    {
    }

private:
    enum class State {
        CLOSED,
        LISTEN,
        SYN_SENT,
        SYN_RCVD,
        ESTABLISHED,
        CLOSE_WAIT,
        LAST_ACK,
        FIN_WAIT_1,
        FIN_WAIT_2,
        CLOSING,
        TIME_WAIT,
    };

    State state;

    // Receive portion of the TCB
    struct {
        // Receive Next
        u32 NXT;
        // Receive Window
        u16 WND;
        // Receive Urgent Pointer
        u16 UP;
        // Initial Receive Sequence Number
        u32 IRS;
    } RCV;

    // Send portion of the TCB
    struct {
        // Send Unacknowledged
        u32 UNA;
        // Send Next
        u32 NXT;
        // Send Window
        u16 WND;
        // Send Urgent Pointer
        u16 UP;
        // Segment Sequence Number Used For Last Window Update
        u32 WL1;
        // Segment Acknowledgement Number Used For Last Window Update
        u32 WL2;
        // Initial Send Sequence Number
        u32 ISS;
    } SND;
};
