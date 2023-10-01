//
// Created by Ryan Wolk on 9/30/23.
//

#include "FIFOLock.h"

void FIFOLock::lock()
{
    std::unique_lock guard (m_mutex);

    if (!locked) {
        locked = true;
        return;
    }

    m_ticket_tail++;
    size_t ticket = m_ticket_tail;

    cv.wait(guard, [&]() {
        return m_ticket_head == ticket;
    });
}

bool FIFOLock::try_lock()
{
    std::unique_lock guard (m_mutex);

    if (!locked) {
        locked = true;
        return true;
    }

    // In this case, don't block on attempting to get in the queue
    return false;
}

void FIFOLock::unlock()
{
    std::unique_lock guard (m_mutex);

    if (m_ticket_head == m_ticket_tail) {
        locked = false;
        return;
    }

    m_ticket_head++;
    cv.notify_all();
}
