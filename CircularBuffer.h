//
// Created by Ryan Wolk on 8/15/23.
//

#pragma once

#include <memory>
#include "IntDefs.h"

class VLBuffer;
class VLBufferView;

class CircularBuffer {
public:
    explicit CircularBuffer(size_t length);

    bool Write(VLBufferView);
    VLBuffer Read(size_t byte_count);

    size_t RemainingSpace() const;
    size_t GetLength() const { return m_length; }

private:
    std::unique_ptr<u8[]> m_internal_data;
    size_t m_length;
    size_t m_write_offset { };
    size_t m_read_offset { };

    bool m_fully_used { false };
};