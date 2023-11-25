//
// Created by Ryan Wolk on 4/23/22.
//

#pragma once

#include <functional>
#include <mutex>
#include <thread>

template <typename T>
class FixedTimer {
    struct TimerNode {
        T* value;
        std::chrono::steady_clock::time_point time;
        TimerNode* next;
    };

public:
    struct TimerRef {
        void* list_ptr;
    };

    FixedTimer(std::chrono::milliseconds millis, std::function<void(T)> fn)
        : timeout_period(millis)
        , m_callback(fn)
    {
    }

    [[noreturn]] void Loop()
    {
        for (;;) {
            if (first != nullptr) {
                std::unique_lock lock(m_list_mutex);
                const auto time = first->time;
                lock.unlock();

                std::this_thread::sleep_until(time);

                lock.lock();
                const auto now = std::chrono::steady_clock::now();

                for (auto* it = first; it != nullptr;) {
                    if (it->time > now) {
                        break;
                    }

                    m_callback(it->value);

                    auto* next_it = it->next;
                    first = next_it;

                    delete it;

                    it = next_it;
                }
            }
        }
    }

    TimerRef AddTimer(T* value)
    {
        const auto now = std::chrono::steady_clock::now();
        std::scoped_lock lock(m_list_mutex);

        if (last == nullptr) {
            first = new TimerNode(value, now + timeout_period, nullptr);
            last = first;
        } else {
            last->next = new TimerNode(value, now + timeout_period, nullptr);
            last = last->next;
        }

        return { last };
    }

    void RemoveTimer(TimerRef)
    {
        std::scoped_lock lock(m_list_mutex);
    }

private:
    std::mutex m_list_mutex;
    TimerNode* first { nullptr };
    TimerNode* last { nullptr };

    const std::chrono::milliseconds timeout_period;
    std::function<void(T)> m_callback;
};
