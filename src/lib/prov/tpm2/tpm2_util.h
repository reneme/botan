/*
* TPM 2 internal utilities
* (C) 2024 Jack Lloyd
* (C) 2024 René Meusel, Amos Treiber - Rohde & Schwarz Cybersecurity GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_TPM2_UTIL_H_
#define BOTAN_TPM2_UTIL_H_

#include <botan/concepts.h>
#include <botan/tpm2.h>

#include <tss2/tss2_esys.h>
#include <tss2/tss2_rc.h>

#include <memory>
#include <span>

namespace Botan::TPM2 {

inline void check_tss2_rc(std::string_view location, TSS2_RC rc) {
   if(rc != TSS2_RC_SUCCESS) {
      throw Error(location, rc);
   }
}

template <typename T>
concept tpm2_buffer = requires(T t) {
   { t.buffer } -> std::convertible_to<const uint8_t*>;
   { t.size } -> std::convertible_to<size_t>;
};

auto as_span(tpm2_buffer auto& data) {
   return std::span{data.buffer, data.size};
}

template <tpm2_buffer T>
T copy_into(std::span<const uint8_t> data) {
   T result;
   BOTAN_ASSERT_NOMSG(data.size() <= sizeof(result.buffer));
   result.size = static_cast<decltype(result.size)>(data.size());
   copy_mem(as_span(result), data);
   return result;
}

template <concepts::resizable_byte_buffer OutT>
OutT copy_into(const tpm2_buffer auto& data) {
   OutT result;
   result.resize(data.size);
   copy_mem(result, as_span(data));
   return result;
}

template <tpm2_buffer T>
T init_empty() {
   T result;
   result.size = 0;
   return result;
}

inline ESYS_CONTEXT* inner(const std::shared_ptr<Context>& ctx) {
   BOTAN_ASSERT_NOMSG(ctx != nullptr);
   auto inner = ctx->inner_context_object();
   BOTAN_ASSERT_NOMSG(inner != nullptr);
   return static_cast<ESYS_CONTEXT*>(inner);
}

struct esys_liberator {
      void operator()(void* handle) { Esys_Free(handle); }
};

template <typename T>
using unique_esys_ptr = std::unique_ptr<T, esys_liberator>;

struct PublicInfo {
      unique_esys_ptr<TPM2B_PUBLIC> pub;
      unique_esys_ptr<TPM2B_NAME> name;
      unique_esys_ptr<TPM2B_NAME> qualified_name;
};

struct ObjectHandles {
      std::optional<TPM2_HANDLE> persistent = std::nullopt;
      ESYS_TR transient = ESYS_TR_NONE;
};

}  // namespace Botan::TPM2

#endif
