//
// Created by Ryan Wolk on 6/4/23.
//

#pragma once

#include <cstddef>

inline size_t hash_combine(size_t hash1, size_t hash2)
{
    return hash1 ^ (hash2 + 0x9e3779b9 + (hash1<<6) + (hash1>>2));
}