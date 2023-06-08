//
// Created by Ryan Wolk on 3/14/22.
//

#pragma once

#include <arpa/inet.h>
#include <compare>
#include <concepts>

template <std::integral T>
T host_to_network(T num)
{
    if constexpr (sizeof(T) == 8) {
        return htonll(num);
    } else if constexpr (sizeof(T) == 4) {
        return htonl(num);
    } else if constexpr (sizeof(T) == 2) {
        return htons(num);
    } else if constexpr (sizeof(T) == 1) {
        return num;
    } else {
        static_assert(sizeof(T) != 1
                && sizeof(T) != 2
                && sizeof(T) != 4
                && sizeof(T) != 8,
            "T must be 8, 4, 2, or 1 bytes long");
    }
}

template <std::integral T>
T network_to_host(T num)
{
    if constexpr (sizeof(T) == 8) {
        return ntohll(num);
    } else if constexpr (sizeof(T) == 4) {
        return ntohl(num);
    } else if constexpr (sizeof(T) == 2) {
        return ntohs(num);
    } else if constexpr (sizeof(T) == 1) {
        return num;
    } else {
        static_assert(sizeof(T) != 1
                && sizeof(T) != 2
                && sizeof(T) != 4
                && sizeof(T) != 8,
            "T must be 8, 4, 2, or 1 bytes long");
    }
}

template <std::integral T>
class NetworkOrdered {
public:
    static NetworkOrdered<T> WithNetworkOrder(T value)
    {
        return *reinterpret_cast<NetworkOrdered<T>*>(&value);
    }

    NetworkOrdered()
        : m_value(0)
    {
    }

    // Yes I do want implicit conversions
    NetworkOrdered(T value) // NOLINT
        : m_value(host_to_network(value))
    {
    }

    operator T() const // NOLINT
    {
        return network_to_host(m_value);
    }

    std::strong_ordering operator<=>(T other) const
    {
        auto host_val = network_to_host(m_value);

        if (host_val < other) {
            return std::strong_ordering::less;
        } else if (host_val > other) {
            return std::strong_ordering::greater;
        }

        return std::strong_ordering::equal;
    }

    T Convert() const { return network_to_host(m_value); };

private:
    T m_value;
} __attribute__((packed));