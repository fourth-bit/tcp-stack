//
// Created by Ryan Wolk on 10/11/23.
//

#pragma once

#include <chrono>
#include <functional>
#include <thread>
#include <unordered_set>

class TimerManager {
public:
    TimerManager();
    ~TimerManager();

    TimerManager(TimerManager&&) = delete;
    TimerManager(const TimerManager&) = delete;

    // Add a timer to the manager's queue. Returns a file descriptor to the timer
    // used to identify the fd for a call to RemoveTimer
    int AddTimer(std::chrono::nanoseconds, std::function<void()> callback);
    // Returns true on success
    bool RemoveTimer(int fd);

    void Workfn();

private:
    std::mutex m_lock;

    std::thread m_work_thread;

    int m_epoll_fd;
    int m_notify_fd;
    int m_wake_up_fd;
    bool ready { false };
    std::unordered_map<int, std::function<void()>> m_timer_fds;
};
