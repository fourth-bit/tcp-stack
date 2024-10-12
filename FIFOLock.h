//
// Created by Ryan Wolk on 9/30/23.
//

#pragma once

#include <condition_variable>
#include <list>
#include <mutex>

class FIFOLock {
public:
    void lock();
    bool try_lock();
    void unlock();

private:
    std::mutex m_mutex;
    std::condition_variable cv;
    size_t m_ticket_head { 0 }, m_ticket_tail { 0 };
    bool locked;
};
