//
// Created by Ryan Wolk on 6/21/22.
//

#pragma once

template <typename T>
struct Badge {
    friend T;

private:
    Badge() = default;
};
