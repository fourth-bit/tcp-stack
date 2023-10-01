//
// Created by Ryan Wolk on 9/30/23.
//

#pragma once

#include <mutex>
#include <list>
#include <condition_variable>

class FIFOLock {
public:
    void lock();
    bool try_lock();
    void unlock();

private:
    std::mutex m_mutex;
    std::condition_variable cv;
    size_t m_ticket_head, m_ticket_tail { 0 };
    bool locked;
};
