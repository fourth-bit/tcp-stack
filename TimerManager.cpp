//
// Created by Ryan Wolk on 10/11/23.
//

#include "TimerManager.h"
#include "IntDefs.h"

#include <mutex>
#include <sys/epoll.h>
#include <sys/timerfd.h>

TimerManager::TimerManager()
    : m_work_thread(std::thread([this] { this->Workfn(); }))
{
    m_epoll_fd = epoll_create1(0);

    int fds[2];
    pipe(fds);

    // Order matters here: Only fds[1] can be written to, and fds[0] can only be read from
    m_notify_fd = fds[1];
    m_wake_up_fd = fds[0];

    epoll_event ev = {
        .events = EPOLLIN,
        .data = {
            .fd = m_wake_up_fd,
        }
    };

    epoll_ctl(m_epoll_fd, EPOLL_CTL_ADD, m_wake_up_fd, &ev);

    ready = true;
}

TimerManager::~TimerManager()
{
    std::scoped_lock lock (m_lock);

    u8 data[2] = { 0x01, 0x00 };
    write(m_notify_fd, data, 2);

    if (m_work_thread.joinable()) {
        m_work_thread.join();
    }

    for (auto [key, _] : m_timer_fds) {
        close(key);
    }

    close(m_epoll_fd);
    close(m_notify_fd);
    close(m_wake_up_fd);
}

int TimerManager::AddTimer(std::chrono::nanoseconds duration, std::function<void ()> callback)
{
    int fd = timerfd_create(CLOCK_MONOTONIC, 0);

    auto seconds = std::chrono::duration_cast<std::chrono::seconds>(duration);
    auto nanoseconds = duration - seconds;
    static_assert(std::is_same_v<decltype(nanoseconds), decltype(duration)>);

    itimerspec new_value {
        .it_interval = {
            0,
            0,
        },
        .it_value = {
            .tv_sec = seconds.count(),
            .tv_nsec = nanoseconds.count(),
        }
    };

    if (timerfd_settime(fd, 0, &new_value, nullptr) == -1) {
        return -1;
    }

    epoll_event ev {
        .events = EPOLLIN,
        .data = {
            .fd = fd,
        },
    };

    std::scoped_lock lock (m_lock);

    if (epoll_ctl(m_epoll_fd, EPOLL_CTL_ADD, fd, &ev) == -1) {
        close(fd);
        return -1;
    }

    // Use move semantics because there might be non-trivially copyable data
    // in the lambda capture
    m_timer_fds[fd] = std::move(callback);

    return fd;
}

bool TimerManager::RemoveTimer(int fd)
{
    std::scoped_lock lock (m_lock);

    // If during locking, it was removed for some reason, exit early
    if (!m_timer_fds.contains(fd)) {
        return false;
    }

    if (epoll_ctl(m_epoll_fd, EPOLL_CTL_DEL, fd, nullptr) == -1) {
        return false;
    }

    m_timer_fds.erase(fd);
    close(fd);

    return true;
}

void TimerManager::Workfn()
{
    while (!ready);

    while (true) {
        epoll_event ev;
        epoll_wait(m_epoll_fd, &ev, 1, -1);

        // Will always been fd in the union because that is the only data that
        // we will pass to epoll_ctl.
        int fd = ev.data.fd;

        if (fd == m_wake_up_fd) {
            // For now, this is the only behavior associated with this signal
            break;
        }

        // Need a lock to make sure that events cannot be deleted in a race condition
        std::unique_lock lock (m_lock);

        if (!m_timer_fds.contains(fd)) {
            // Just ignore it if it has been removed
            continue;
        }

        auto function = std::move(m_timer_fds[fd]);

        // Avoid a possible deadlock situation inside the callback
        lock.unlock();

        // Invoke the callback
        function();

        // Destroy the timer
        epoll_ctl(m_epoll_fd, EPOLL_CTL_DEL, fd, nullptr);
        close(fd);
        m_timer_fds.erase(fd);
    }
}
