//
// Created by Ryan Wolk on 6/13/23.
//

#pragma once

#include <concepts>

struct Closed {};
struct LowerOpen {};
struct UpperOpen {};
struct BothOpen {};

template<std::integral T>
class Modular {
public:
    Modular() = default;

    // Intentionally nonexplicit
    Modular(T t)
        : m_data(t)
    {
    }

    bool InRange(Modular<T> lower_bound, Modular<T> upper_bound, Closed) {

        if (lower_bound < upper_bound) {
            // Easy case, normal range check
            return lower_bound <= *this && upper_bound >= *this;
        } else if (lower_bound > upper_bound) {
            // Both cannot be true in this case, only one can be or none can be
            return lower_bound <= *this || upper_bound >= *this;
        } else {
            // They are equal, only the fully closed mode returns true
            return true;
        }
    }
    bool InRange(Modular<T> lower_bound, Modular<T> upper_bound, LowerOpen) {

        if (lower_bound < upper_bound) {
            // Easy case, normal range check
            return lower_bound < *this && upper_bound >= *this;
        } else if (lower_bound > upper_bound) {
            // Both cannot be true in this case, only one can be or none can be
            return lower_bound < *this || upper_bound >= *this;
        } else {
            // They are equal, only the fully closed mode returns true
            return false;
        }
    }
    bool InRange(Modular<T> lower_bound, Modular<T> upper_bound, UpperOpen) {

        if (lower_bound < upper_bound) {
            // Easy case, normal range check
            return lower_bound <= *this && upper_bound > *this;
        } else if (lower_bound > upper_bound) {
            // Both cannot be true in this case, only one can be or none can be
            return lower_bound <= *this || upper_bound > *this;
        } else {
            // They are equal, only the fully closed mode returns true
            return false;
        }
    }
    bool InRange(Modular<T> lower_bound, Modular<T> upper_bound, BothOpen) {

        if (lower_bound < upper_bound) {
            // Easy case, normal range check
            return lower_bound < *this && upper_bound > *this;
        } else if (lower_bound > upper_bound) {
            // Both cannot be true in this case, only one can be or none can be
            return lower_bound < *this || upper_bound > *this;
        } else {
            // They are equal, only the fully closed mode returns true
            return false;
        }
    }

    bool operator==(Modular<T> other) const
    {
        return other.m_data == m_data;
    }
    bool operator==(T other) const
    {
        return other == m_data;
    }

    // Fixme: Relying on overflow working like this is UB
    Modular<T> operator+(T other)
    {
        return Modular(m_data + other);
    }
    Modular<T> operator+(Modular<T> other)
    {
        return Modular(m_data + other.m_data);
    }
    Modular<T> operator-(T other)
    {
        return Modular(m_data - other);
    }
    Modular<T> operator-(Modular<T> other)
    {
        return Modular(m_data - other.m_data);
    }

    void operator+=(T other)
    {
        m_data += other;
    }
    void operator+=(Modular<T> other)
    {
        m_data += other.m_data;
    }

    // The Unsafe CMP suite of functions implements the comparison operators such that
    // a half a revolution past m_data is greater than, and the other half is less than
    // These methods should only be used in cases where the values are assumed to be close
    // enough to the originals such that this distinction means very little.
    bool UnsafeLT(Modular<T> other)
    {
        constexpr int bits = sizeof(T);
        constexpr T half_rev_T = 1 << (bits - 1);
        Modular<T> half_revolution = *this - half_rev_T;

        return other.InRange(half_revolution, *this, BothOpen{});
    }
    bool UnsafeLE(Modular<T> other)
    {
        constexpr int bits = sizeof(T);
        constexpr T half_rev_T = 1 << (bits - 1);
        Modular<T> half_revolution = *this - half_rev_T;

        return other.InRange(half_revolution, *this, LowerOpen {});
    }
    bool UnsafeGT(Modular<T> other)
    {
        return !UnsafeLE(other);
    }
    bool UnsafeGE(Modular<T> other)
    {
        return !UnsafeLT(other);
    }

    T& Get() { return m_data; }

private:
    // For internal use in Modular::InRange
    std::strong_ordering operator<=>(Modular<T> other)
    {
        return m_data <=> other.m_data;
    }

    T m_data;
};
