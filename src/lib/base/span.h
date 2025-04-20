/*
* C++17 std::span adapter
* (C) 2025 Jack Lloyd
* (C) 2025 René Meusel
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_STD_SPAN_ADAPTER_H_
#define BOTAN_STD_SPAN_ADAPTER_H_

#include <botan/build.h>

#if !defined(BOTAN_CPP17_COMPATIBILITY_MODE)
#include <span>
#else
#define TCB_SPAN_NAMESPACE_NAME std
#include <span.hpp>
#endif

#endif
