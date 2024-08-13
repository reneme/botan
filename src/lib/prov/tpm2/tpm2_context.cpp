/*
* TPM 2 interface
* (C) 2024 Jack Lloyd
* (C) 2024 René Meusel, Amos Treiber - Rohde & Schwarz Cybersecurity GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/tpm2_context.h>

#include <botan/tpm2_rsa.h>
#include <botan/tpm2_session.h>

#include <botan/internal/fmt.h>
#include <botan/internal/loadstor.h>
#include <botan/internal/stl_util.h>
#include <botan/internal/tpm2_util.h>

#include <tss2/tss2_esys.h>
#include <tss2/tss2_tcti.h>
#include <tss2/tss2_tctildr.h>

#if defined(BOTAN_HAS_TPM2_CRYPTO_BACKEND)
   #include <botan/internal/tpm2_crypto_backend.h>
#endif

namespace Botan::TPM2 {

namespace {

constexpr TPM2_HANDLE storage_root_key_handle = TPM2_HR_PERSISTENT + 1;

}  // namespace

struct Context::Impl {
      TSS2_TCTI_CONTEXT* m_tcti_ctx;
      ESYS_CONTEXT* m_ctx;

#if defined(BOTAN_HAS_TPM2_CRYPTO_BACKEND)
      std::unique_ptr<CryptoCallbackState> m_crypto_callback_state;
#endif
};

bool Context::supports_botan_crypto_backend() noexcept {
#if defined(BOTAN_TSS2_SUPPORTS_CRYPTO_CALLBACKS) and defined(BOTAN_HAS_TPM2_CRYPTO_BACKEND)
   return true;
#else
   return false;
#endif
}

std::shared_ptr<Context> Context::create(const std::string& tcti_nameconf) {
   // We cannot std::make_shared as the constructor is private
   return std::shared_ptr<Context>(new Context(tcti_nameconf.c_str()));
}

std::shared_ptr<Context> Context::create(std::optional<std::string> tcti, std::optional<std::string> conf) {
   const auto tcti_ptr = tcti.has_value() ? tcti->c_str() : nullptr;
   const auto conf_ptr = conf.has_value() ? conf->c_str() : nullptr;

   // We cannot std::make_shared as the constructor is private
   return std::shared_ptr<Context>(new Context(tcti_ptr, conf_ptr));
}

Context::Context(const char* tcti_nameconf) : m_impl(std::make_unique<Impl>()) {
   check_rc("TCTI Initialization", Tss2_TctiLdr_Initialize(tcti_nameconf, &m_impl->m_tcti_ctx));
   check_rc("TPM2 Initialization", Esys_Initialize(&m_impl->m_ctx, m_impl->m_tcti_ctx, nullptr /* ABI version */));
}

Context::Context(const char* tcti_name, const char* tcti_conf) : m_impl(std::make_unique<Impl>()) {
   check_rc("TCTI Initialization", Tss2_TctiLdr_Initialize_Ex(tcti_name, tcti_conf, &m_impl->m_tcti_ctx));
   check_rc("TPM2 Initialization", Esys_Initialize(&m_impl->m_ctx, m_impl->m_tcti_ctx, nullptr /* ABI version */));
}

void Context::use_botan_crypto_backend(const std::shared_ptr<Botan::RandomNumberGenerator>& rng) {
#if defined(BOTAN_HAS_TPM2_CRYPTO_BACKEND)
   BOTAN_ASSERT_NOMSG(!m_impl->m_crypto_callback_state);
   m_impl->m_crypto_callback_state = std::make_unique<CryptoCallbackState>(rng);
   enable_crypto_callbacks(shared_from_this());
#else
   BOTAN_UNUSED(rng);
   throw Not_Implemented("This build of botan does not provide the TPM2 crypto backend");
#endif
}

#if defined(BOTAN_HAS_TPM2_CRYPTO_BACKEND)
CryptoCallbackState& Context::crypto_callback_state() {
   BOTAN_ASSERT_NONNULL(m_impl->m_crypto_callback_state);
   return *m_impl->m_crypto_callback_state;
}
#endif

void* Context::inner_context_object() {
   return m_impl->m_ctx;
}

namespace {

uint32_t get_tpm_property(ESYS_CONTEXT* ctx, TPM2_PT property) {
   // We expect to retrieve a single piece of information, not a list.
   constexpr uint32_t property_count = 1;
   constexpr TPM2_CAP capability = TPM2_CAP_TPM_PROPERTIES;

   unique_esys_ptr<TPMS_CAPABILITY_DATA> capability_data;
   check_rc("Esys_GetCapability",
            Esys_GetCapability(ctx,
                               ESYS_TR_NONE,
                               ESYS_TR_NONE,
                               ESYS_TR_NONE,
                               capability,
                               property,
                               property_count,
                               nullptr /* more data? - we don't care here */,
                               out_ptr(capability_data)));
   BOTAN_ASSERT_NONNULL(capability_data);
   BOTAN_ASSERT_NOMSG(capability_data->capability == capability);
   BOTAN_ASSERT_NOMSG(capability_data->data.tpmProperties.count == property_count);
   BOTAN_ASSERT_NOMSG(capability_data->data.tpmProperties.tpmProperty[0].property == property);

   return capability_data->data.tpmProperties.tpmProperty[0].value;
}

template <TPM2_CAP capability>
[[nodiscard]] auto get_tpm_property_list(ESYS_CONTEXT* ctx, TPM2_PT property, uint32_t count) {
   auto extract = [](const TPMU_CAPABILITIES& caps, uint32_t max_count) {
      if constexpr(capability == TPM2_CAP_HANDLES) {
         const auto to_read = std::min(caps.handles.count, max_count);
         std::vector<uint32_t> result;
         result.reserve(to_read);
         for(size_t i = 0; i < to_read; ++i) {
            result.push_back(caps.handles.handle[i]);
         }
         return result;
      } else {
         // TODO: support reading other capability types as needed
         static_assert(capability != TPM2_CAP_HANDLES, "Unsupported capability");
      }
   };

   using return_vector_t = decltype(extract(std::declval<const TPMU_CAPABILITIES&>(), 0));
   static_assert(concepts::reservable_container<return_vector_t>);

   TPMI_YES_NO more_data = TPM2_YES;
   return_vector_t properties;
   while(more_data == TPM2_YES && count > 0) {
      unique_esys_ptr<TPMS_CAPABILITY_DATA> capability_data;
      check_rc("Esys_GetCapability",
               Esys_GetCapability(ctx,
                                  ESYS_TR_NONE,
                                  ESYS_TR_NONE,
                                  ESYS_TR_NONE,
                                  capability,
                                  property,
                                  count,
                                  &more_data,
                                  out_ptr(capability_data)));
      BOTAN_ASSERT_NONNULL(capability_data);
      BOTAN_ASSERT_NOMSG(capability_data->capability == capability);

      const auto new_properties = extract(capability_data->data, count);
      BOTAN_ASSERT_NOMSG(new_properties.size() <= count);
      properties.insert(properties.end(), new_properties.begin(), new_properties.end());
      count -= new_properties.size();
   }

   return properties;
}

}  // namespace

std::string Context::vendor() const {
   constexpr std::array properties = {
      TPM2_PT_VENDOR_STRING_1, TPM2_PT_VENDOR_STRING_2, TPM2_PT_VENDOR_STRING_3, TPM2_PT_VENDOR_STRING_4};
   std::array<uint8_t, properties.size() * 4 + 1 /* ensure zero-termination */> vendor_string{};

   BufferStuffer bs(vendor_string);

   // The vendor name is transported in several uint32_t fields that are
   // loaded as big-endian bytes and concatenated to form the vendor string.
   for(auto prop : properties) {
      bs.append(store_be(get_tpm_property(m_impl->m_ctx, prop)));
   }

   BOTAN_ASSERT_NOMSG(bs.remaining_capacity() == 1);  // the ensured zero-termination
   return std::string(cast_uint8_ptr_to_char(vendor_string.data()));
}

std::string Context::manufacturer() const {
   std::array<uint8_t, 4 + 1 /* ensure zero termination */> manufacturer_data{};
   store_be(std::span{manufacturer_data}.first<4>(), get_tpm_property(m_impl->m_ctx, TPM2_PT_MANUFACTURER));
   return std::string(cast_uint8_ptr_to_char(manufacturer_data.data()));
}

size_t Context::max_random_bytes_per_request() const {
   return get_tpm_property(m_impl->m_ctx, TPM2_PT_MAX_DIGEST);
}

std::unique_ptr<RSA_PrivateKey> Context::storage_root_key(std::span<const uint8_t> auth_value,
                                                          const SessionBundle& sessions) {
   // TODO: allow loading ECC-based keys as well
   //       (probably by providing a generic 'from_persistent' function that
   //       detects the key type automatically and returns a suitable object)
   return RSA_PrivateKey::from_persistent(shared_from_this(), storage_root_key_handle, auth_value, sessions);
}

std::optional<uint32_t> Context::find_free_persistent_handle() const {
   const auto occupied_handles = persistent_handles();

   // This is modeled after the implementation in tpm2-tools, which also takes
   // "platform persistent" handles into account. We don't do that here, but
   // we might need to in the future.
   //
   // See: https://github.com/tpm2-software/tpm2-tools/blob/bd832d3f79299c5aaaf86667a74c3230f3101e44/lib/tpm2_capability.c#L143-L196

   // all persistent handles are occupied
   if(occupied_handles.size() >= TPM2_MAX_CAP_HANDLES) {
      return std::nullopt;
   }

   // find the lowest handle that is not occupied
   for(uint32_t i = TPM2_PERSISTENT_FIRST; i < TPM2_PERSISTENT_LAST; ++i) {
      if(!value_exists(occupied_handles, i)) {
         return i;
      }
   }

   BOTAN_ASSERT_UNREACHABLE();
}

std::vector<uint32_t> Context::persistent_handles() const {
   return get_tpm_property_list<TPM2_CAP_HANDLES>(m_impl->m_ctx, TPM2_PERSISTENT_FIRST, TPM2_MAX_CAP_HANDLES);
}

bool Context::in_persistent_handles(uint32_t persistent_handle) const {
   auto persistent_handles = this->persistent_handles();
   return std::find(persistent_handles.begin(), persistent_handles.end(), persistent_handle) !=
          persistent_handles.end();
}

void Context::make_key_persistent(RSA_PrivateKey& key, uint32_t persistent_handle, const SessionBundle& sessions) {
   if(in_persistent_handles(persistent_handle)) {
      throw Invalid_Argument("Persistent handle already in use");
   }

   ESYS_TR persistent_handle_out;

   check_rc("Esys_EvictControl",
            Esys_EvictControl(m_impl->m_ctx,
                              ESYS_TR_RH_OWNER /*TODO: hierarchy*/,
                              key.handles().transient_handle(),
                              sessions[0],
                              sessions[1],
                              sessions[2],
                              persistent_handle,
                              &persistent_handle_out));

   check_rc("Esys_TR_GetTpmHandle",
            Esys_TR_GetTpmHandle(m_impl->m_ctx, persistent_handle_out, out_persistent_handle(key.mutable_handles())));

   BOTAN_ASSERT_NOMSG(persistent_handle == key.handles().persistent_handle());
}

void Context::evict_persistent_key(RSA_PrivateKey& key, const SessionBundle& sessions) {
   ESYS_TR persistent_handle_out;

   // TODO: This is not the right call yet...
   check_rc("Esys_EvictControl",
            Esys_EvictControl(m_impl->m_ctx,
                              ESYS_TR_RH_OWNER /*TODO: hierarchy*/,
                              key.handles().transient_handle(),
                              sessions[0],
                              sessions[1],
                              sessions[2],
                              key.handles().persistent_handle(),
                              &persistent_handle_out));

   // TODO: Will this clear the persistent handle in the key object?
   // check_rc("Esys_TR_GetTpmHandle",
   //          Esys_TR_GetTpmHandle(m_impl->m_ctx, persistent_handle_out, out_persistent_handle(key.mutable_handles())));
}

Context::~Context() {
   if(m_impl) {
      Esys_Finalize(&m_impl->m_ctx);
      Tss2_TctiLdr_Finalize(&m_impl->m_tcti_ctx);
   }
}

}  // namespace Botan::TPM2
