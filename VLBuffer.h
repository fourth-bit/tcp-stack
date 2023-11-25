//
// Created by Ryan Wolk on 3/25/22.
//

#pragma once

#include "IntDefs.h"
#include <cstdio>
#include <cstdlib>

class VLBuffer;

class VLBufferView {
    friend class VLBuffer;

public:
    VLBufferView SubBuffer(size_t index)
    {
        if (index >= m_length) {
            // Todo: Error
        }

        return { m_data, index, m_length };
    }

    VLBufferView ShrinkEnd(size_t end_index)
    {
        if (end_index >= m_length) {
            // Todo: Error
        }

        return { m_data, 0, end_index };
    }

    u8& operator[](size_t index)
    {
        if (index >= m_length) {
            // Todo: Error
        }

        return m_data[index];
    }

    inline VLBuffer CopyToVLBuffer(); // Must be marked in header

    u8* Data() { return m_data; }
    const u8* Data() const { return m_data; }
    size_t Size() const { return m_length; }

    template <typename T>
    T& as()
    {
        return *reinterpret_cast<T*>(m_data);
    }

private:
    VLBufferView(u8* ptr, size_t offset, size_t length)
        : m_data(ptr + offset)
        , m_length(length - offset)
    {
    }

    u8* m_data;
    size_t m_length;
};

class VLBuffer {
    friend class VLBufferView;

public:
    VLBuffer(VLBuffer&& other) noexcept
    {
        m_data = other.m_data;
        m_length = other.m_length;

        other.m_data = nullptr;
        other.m_length = 0;
    }
    VLBuffer& operator=(VLBuffer&& other) noexcept
    {
        if (&other != this) {
            m_data = other.m_data;
            m_length = other.m_length;

            other.m_data = nullptr;
            other.m_length = 0;
        }

        return *this;
    }
    ~VLBuffer()
    {
        free(m_data);
    }

    static VLBuffer WithSize(size_t length)
    {
        auto* ptr = (u8*)malloc(length);
        if (ptr == nullptr) {
            // Todo: Error
        }

        return VLBuffer { ptr, length };
    }

    u8& operator[](size_t len)
    {
        if (len > m_length) {
            // Todo: Error
        }
        return m_data[len];
    }

    u8* Data() { return m_data; }
    size_t Size() const { return m_length; }

    template <typename T>
    T& as()
    {
        return *reinterpret_cast<T*>(m_data);
    }

    VLBufferView AsView()
    {
        return { m_data, 0, m_length };
    }

    void Hexdump()
    {
        printf("Printing hexdump:\n");
        for (size_t i = 0; i < m_length; i++) {
            if (i % 8 == 0) {
                printf("\n");
            }
            printf("%02x ", m_data[i]);
        }

        printf("\n");
        fflush(stdout);
    }

    void Resize(size_t length)
    {
        if (m_length < length) {
            // Todo: error
            return;
        }

        m_length = length;
    }

    VLBuffer Copy() const
    {
        auto new_buf = VLBuffer::WithSize(m_length);
        std::copy(m_data, m_data + m_length, new_buf.m_data);

        return new_buf;
    }

private:
    VLBuffer(u8* ptr, size_t length)
        : m_data(ptr)
        , m_length(length)
    {
    }

    u8* m_data;
    size_t m_length;
};

inline VLBuffer VLBufferView::CopyToVLBuffer()
{
    auto new_buf = VLBuffer::WithSize(m_length);
    std::copy(m_data, m_data + m_length, new_buf.m_data);

    return new_buf;
}