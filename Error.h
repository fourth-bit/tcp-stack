//
// Created by Ryan Wolk on 4/1/23.
//

// FIXME: Name conflict with error.h in the c standard library

#pragma once

#include <memory>
#include <variant>

class Error {
public:
    virtual ~Error() = default;

    virtual std::string ToString() = 0;
};

template<typename T>
class ErrorOr {
public:
    ErrorOr(std::unique_ptr<Error> error)
        : m_variant(std::move(error))
    {
    }
    ErrorOr(T t)
        : m_variant(std::move(t))
    {
    }

    T& GetResult()
    {
        return std::get<T>(m_variant);
    }

    Error* GetError()
    {
        return std::get<std::unique_ptr<Error>>(m_variant).get();
    }

    bool IsError()
    {
        return !std::holds_alternative<T>(m_variant);
    }

private:
    std::variant<std::unique_ptr<Error>, T> m_variant;
};