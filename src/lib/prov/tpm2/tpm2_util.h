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
#include <botan/mem_ops.h>
#include <botan/tpm2_context.h>
#include <botan/tpm2_error.h>
#include <botan/tpm2_object.h>

#include <botan/internal/fmt.h>

#include <tss2/tss2_esys.h>
#include <tss2/tss2_rc.h>

#include <bit>
#include <memory>
#include <span>

// There's no obvious way to get the version of the TSS from its headers,
// instead the existence of certain return code macro definitions is used
// as sentinels to pinpoint the TSS' version. Namely:
//
//   - TSS2_BASE_RC_CALLBACK_NULL -> 4.0.0 or later
//   - TPM2_RC_FW_LIMITED         -> 4.1.0 or later

#if defined(TSS2_BASE_RC_CALLBACK_NULL)
   // The crypto callbacks were added in tpm2-tss 4.0.0.
   #define BOTAN_TSS2_SUPPORTS_CRYPTO_CALLBACKS

   // Error decoding was added in tpm2-tss 4.0.0
   #define BOTAN_TSS2_SUPPORTS_ERROR_DECODING
#endif

#if defined(TPM2_RC_FW_LIMITED)
   // The crypto callbacks for SM4 were added in tpm2-tss 4.1.0.
   #define BOTAN_TSS2_SUPPORTS_SM4_IN_CRYPTO_CALLBACKS
#endif

namespace Botan::TPM2 {

/**
 * Check the return code and throw an exception if some error occured.
 *
 * @throws TPM2::Error if an error occured.
 */
constexpr void check_rc(std::string_view location, TSS2_RC rc) {
   if(rc != TSS2_RC_SUCCESS) {
      throw Error(location, rc);
   }
}

/**
 * Check the return code and throw an exception if an unexpected error occured.
 *
 * Errors that are listed in the `expected_errors` parameter are considered
 * expected and will not cause an exception to be thrown. Instead the error
 * code is decoded and returned to the caller for further processing.
 *
 * @throws TPM2::Error if an unexpected error occured.
 * @returns TSS2_RC_SUCCESS or one of the expected error codes.
 */
template <TSS2_RC... expected_errors>
   requires(sizeof...(expected_errors) > 0)
[[nodiscard]] constexpr TSS2_RC check_rc_expecting(std::string_view location, TSS2_RC rc) {
   // If the RC is success, we can return early and avoid the decoding.
   if(rc == TSS2_RC_SUCCESS) {
      return rc;
   }

   // An error occured, we need to decode it to check if it was expected.
   const TSS2_RC decoded_rc = get_raw_rc(rc);

   // Check if the error is one of the expected and return those to the caller.
   const bool is_expected_by_caller = ((decoded_rc == expected_errors) || ...);
   if(is_expected_by_caller) {
      return decoded_rc;
   }

   // The error was not expected, so call the normal error handling which
   // will throw an exception.
   check_rc(location, rc);

   // We know, rc is not 'success', so this won't ever be reached.
   return rc;
}

template <typename T>
concept tpm2_buffer = requires(T t) {
   { t.buffer } -> std::convertible_to<const uint8_t*>;
   { t.size } -> std::convertible_to<size_t>;
};

constexpr auto as_span(tpm2_buffer auto& data) {
   return std::span{data.buffer, data.size};
}

template <tpm2_buffer T>
constexpr void copy_into(T& dest, std::span<const uint8_t> data) {
   BOTAN_ASSERT_NOMSG(data.size() <= sizeof(dest.buffer));
   dest.size = static_cast<decltype(dest.size)>(data.size());
   copy_mem(as_span(dest), data);
}

template <tpm2_buffer T>
constexpr T copy_into(std::span<const uint8_t> data) {
   T result;
   copy_into(result, data);
   return result;
}

template <concepts::resizable_byte_buffer OutT>
constexpr OutT copy_into(const tpm2_buffer auto& data) {
   OutT result;
   result.resize(data.size);
   copy_mem(result, as_span(data));
   return result;
}

template <tpm2_buffer T>
constexpr T init_with_size(size_t length) {
   T result;
   BOTAN_ARG_CHECK(length <= sizeof(result.buffer), "Not enough capacity in TPM2 buffer type");
   result.size = static_cast<decltype(result.size)>(length);
   return result;
}

template <tpm2_buffer T>
constexpr T init_empty() {
   return init_with_size<T>(0);
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

class ObjectSetter {
   public:
      constexpr ObjectSetter(Object& object, bool persistent = false) :
            m_object(object), m_persistent(persistent), m_handle(persistent ? 0 : ESYS_TR_NONE) {}

      constexpr ~ObjectSetter() noexcept {
         if(!was_written()) {
            return;
         }

         if(m_persistent) {
            m_object.handles().persistent = m_handle;
         } else {
            m_object.handles().transient = m_handle;
         }
      }

      ObjectSetter(const ObjectSetter&) = delete;
      ObjectSetter(ObjectSetter&&) = delete;
      ObjectSetter& operator=(const ObjectSetter&) = delete;
      ObjectSetter& operator=(ObjectSetter&&) = delete;

      [[nodiscard]] constexpr operator uint32_t*() && noexcept { return &m_handle; }

   private:
      constexpr bool was_written() const { return m_handle != (m_persistent ? 0 : ESYS_TR_NONE); }

   private:
      Object& m_object;
      bool m_persistent;
      uint32_t m_handle;
};

constexpr auto out_transient_handle(Object& object) {
   return ObjectSetter{object, false};
}

constexpr auto out_persistent_handle(Object& object) {
   return ObjectSetter{object, true};
}

/**
 * This is an internal helper structure to wrap TPMA_* attribute bit fields.
 *
 * @tparam UnderlyingT         the TPMA_* bit field type
 * @tparam AttributeWrapperT   the C++ struct type that wraps the TPMA_* bit field
 * @tparam mappings            a bunch of std::pair mappping boolean members of
 *                             AttributeWrapperT to the bit masks of the TPMA_* type
 */
template <std::unsigned_integral UnderlyingT,
          typename AttributeWrapperT,
          std::pair<bool AttributeWrapperT::*, UnderlyingT>... mappings>
class AttributeWrapper {
   private:
      template <std::invocable<bool AttributeWrapperT::*, const UnderlyingT> FnT>
      static constexpr void for_all(FnT&& fn) {
         (fn(mappings.first, mappings.second), ...);
      }

      static consteval bool all_single_bit_bitmasks() {
         bool result = true;
         for_all([&](auto, const auto flag) { result = result && (std::popcount(flag) == 1); });
         return result;
      }

      static_assert(all_single_bit_bitmasks(), "mappings... must contain single-bit flags only");

   public:
      static constexpr UnderlyingT render(AttributeWrapperT attributes) {
         UnderlyingT result = 0;
         for_all([&](auto field, const auto flag) {
            if(attributes.*field) {
               result |= flag;
            }
         });
         return result;
      }

      static constexpr AttributeWrapperT read(UnderlyingT attributes) {
         AttributeWrapperT result;
         for_all([&](auto field, const auto flag) { result.*field = (attributes & flag) != 0; });
         return result;
      }
};

}  // namespace Botan::TPM2

#endif
