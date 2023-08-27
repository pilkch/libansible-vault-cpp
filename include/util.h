#pragma once

#include <cstddef>

namespace vault {

// Implementation of a secure_clear proposal
// https://www.open-std.org/jtc1/sc22/wg21/docs/papers/2019/p1315r3.html
// https://github.com/ojeda/secure_clear/blob/master/example-implementation/secure_clear.h
//
// See also an attempt at adding a cross platform memory clearing function to curl
// https://github.com/nico-abram/curl/blob/30a61f33905d64ceb67c3af08c8548dea3a22fb5/lib/curl_memory.h
void secure_clear(void* data, size_t size) noexcept;

// Constant time memory comparison
// https://github.com/AGWA/git-crypt/blob/master/util.cpp

bool leakless_equals(const unsigned char* a, const unsigned char* b, std::size_t len);
bool leakless_equals(const void* a, const void* b, std::size_t len);


}
