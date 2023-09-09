//
// Created by Ryan Wolk on 8/15/23.
//

#include "CircularBuffer.h"
#include "VLBuffer.h"

CircularBuffer::CircularBuffer(size_t length)
    : m_length(length)
    , m_internal_data(new u8[length])
{
}
bool CircularBuffer::Write(VLBufferView view)
{
    if (view.Size() > RemainingSpace()) {
        return false;
    }

    if (m_write_offset + view.Size() < m_length) {
        // We can fit the entire write in a contiguous space
        const u8* copying_data = view.Data();
        std::copy(copying_data, copying_data + view.Size(), m_internal_data.get() + m_write_offset);

        m_write_offset += view.Size();
    } else {
        const u8* copying_data = view.Data();

        size_t leg1 = m_length - m_write_offset;
        size_t leg2 = view.Size() - leg1;

        std::copy(copying_data, copying_data + leg1, m_internal_data.get() + m_write_offset);
        std::copy(copying_data + leg1, copying_data + view.Size(), m_internal_data.get());

        m_write_offset = leg2;
    }

    if (view.Size() != 0 && m_read_offset == m_write_offset) {
        m_fully_used = true;
    }

    return true;
}
VLBuffer CircularBuffer::Read(size_t byte_count)
{
    // Don't read more bytes than are in the buffer
    size_t size = std::min(m_length - RemainingSpace(), byte_count);

    VLBuffer ret = VLBuffer::WithSize(size);
    u8* write_ptr = ret.Data();

    if (m_read_offset + size < m_length) {
        std::copy(m_internal_data.get() + m_read_offset, m_internal_data.get() + m_read_offset + size, write_ptr);
        m_read_offset += size;
    } else {
        size_t leg1 = m_length - m_read_offset;
        size_t leg2 = size - leg1;

        std::copy(m_internal_data.get() + m_read_offset, m_internal_data.get() + m_read_offset + leg1, write_ptr);
        std::copy(m_internal_data.get(), m_internal_data.get() + leg2, write_ptr + leg1);

        m_read_offset = leg2;
    }

    if (size != 0) {
        m_fully_used = false;
    }

    return ret;
}

size_t CircularBuffer::RemainingSpace() const
{
    if (m_fully_used) {
        return 0;
    }

    // The space is the distance outside the read pointer and the write pointer
    if (m_read_offset <= m_write_offset) {
        return m_length - (m_write_offset - m_read_offset);
    }

    // The distance is the space between the write pointer and the read pointer
    return m_read_offset - m_write_offset;
}
