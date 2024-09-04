/*
* TPM 2 interface
* (C) 2024 Jack Lloyd
* (C) 2024 René Meusel, Amos Treiber - Rohde & Schwarz Cybersecurity GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/tpm2_context.h>

#include <botan/tpm2_key.h>
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

template <TPM2_CAP capability, typename ReturnT>
[[nodiscard]] std::vector<ReturnT> get_tpm_property_list(ESYS_CONTEXT* ctx, TPM2_PT property, uint32_t count) {
   auto extract = [](const TPMU_CAPABILITIES& caps, uint32_t max_count) {
      if constexpr(capability == TPM2_CAP_HANDLES) {
         const auto to_read = std::min(caps.handles.count, max_count);
         std::vector<ReturnT> result;
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

   TPMI_YES_NO more_data = TPM2_YES;
   std::vector<ReturnT> properties;
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

std::unique_ptr<TPM2::PrivateKey> Context::storage_root_key(std::span<const uint8_t> auth_value,
                                                            const SessionBundle& sessions) {
   return TPM2::PrivateKey::load_persistent(shared_from_this(), storage_root_key_handle, auth_value, sessions);
}

std::vector<ESYS_TR> Context::transient_handles() const {
   return get_tpm_property_list<TPM2_CAP_HANDLES, ESYS_TR>(m_impl->m_ctx, TPM2_TRANSIENT_FIRST, TPM2_MAX_CAP_HANDLES);
}

std::optional<TPM2_HANDLE> Context::find_free_persistent_handle() const {
   const auto occupied_handles = persistent_handles();

   // This is modeled after the implementation in tpm2-tools, which also takes
   // "platform persistent" handles into account. We don't do that here, but
   // we might need to in the future.
   //
   // See: https://github.com/tpm2-software/tpm2-tools/blob/bd832d3f79/lib/tpm2_capability.c#L143-L196

   // all persistent handles are occupied
   if(occupied_handles.size() >= TPM2_MAX_CAP_HANDLES) {
      return std::nullopt;
   }

   // find the lowest handle that is not occupied
   for(TPM2_HANDLE i = TPM2_PERSISTENT_FIRST; i < TPM2_PERSISTENT_LAST; ++i) {
      if(!value_exists(occupied_handles, i)) {
         return i;
      }
   }

   BOTAN_ASSERT_UNREACHABLE();
}

std::vector<TPM2_HANDLE> Context::persistent_handles() const {
   return get_tpm_property_list<TPM2_CAP_HANDLES, TPM2_HANDLE>(
      m_impl->m_ctx, TPM2_PERSISTENT_FIRST, TPM2_MAX_CAP_HANDLES);
}

TPM2_HANDLE Context::persist(TPM2::PrivateKey& key,
                             const SessionBundle& sessions,
                             std::span<const uint8_t> auth_value,
                             std::optional<TPM2_HANDLE> persistent_handle) {
   auto& handles = key.handles();

   BOTAN_ARG_CHECK(!persistent_handle || !value_exists(persistent_handles(), persistent_handle.value()),
                   "Persistent handle already in use");
   BOTAN_ARG_CHECK(!handles.has_persistent_handle(), "Key already has a persistent handle assigned");

   // 1. Decide on the location to persist the key to.
   //    This uses either the handle provided by the caller or a free handle.
   const TPMI_DH_PERSISTENT new_persistent_handle = [&] {
      if(persistent_handle.has_value()) {
         return persistent_handle.value();
      } else {
         const auto free_persistent_handle = find_free_persistent_handle();
         BOTAN_STATE_CHECK(free_persistent_handle.has_value());
         return free_persistent_handle.value();
      }
   }();

   // 2. Persist the transient key in the TPM's NV storage
   //    This will flush the transient key handle and replace it with a new
   //    transient handle that references the persisted key.
   check_rc("Esys_EvictControl",
            Esys_EvictControl(m_impl->m_ctx,
                              ESYS_TR_RH_OWNER /*TODO: hierarchy*/,
                              handles.transient_handle(),
                              sessions[0],
                              sessions[1],
                              sessions[2],
                              new_persistent_handle,
                              out_transient_handle(handles)));
   BOTAN_ASSERT_NOMSG(handles.has_transient_handle());

   // 3. Reset the auth value of the key object
   //    This is necessary to ensure that the key object remains usable after
   //    the transient handle was recreated inside Esys_EvictControl().
   if(!auth_value.empty()) {
      const auto user_auth = copy_into<TPM2B_AUTH>(auth_value);
      check_rc("Esys_TR_SetAuth", Esys_TR_SetAuth(m_impl->m_ctx, handles.transient_handle(), &user_auth));
   }

   // 4. Update the key object with the new persistent handle
   //    This double-checks that the key was persisted at the correct location,
   //    but also brings the key object into a consistent state.
   check_rc("Esys_TR_GetTpmHandle",
            Esys_TR_GetTpmHandle(m_impl->m_ctx, handles.transient_handle(), out_persistent_handle(handles)));

   BOTAN_ASSERT_NOMSG(handles.has_persistent_handle());
   BOTAN_ASSERT_EQUAL(new_persistent_handle, handles.persistent_handle(), "key was persisted at the correct location");

   return new_persistent_handle;
}

void Context::evict(std::unique_ptr<TPM2::PrivateKey> key, const SessionBundle& sessions) {
   BOTAN_ASSERT_NONNULL(key);

   auto& handles = key->handles();
   BOTAN_ARG_CHECK(handles.has_persistent_handle(), "Key does not have a persistent handle assigned");

   // 1. Evict the key from the TPM's NV storage
   //    This will free the persistent handle, but the transient handle will
   //    still be valid.
   ESYS_TR no_new_handle = ESYS_TR_NONE;
   check_rc("Esys_EvictControl",
            Esys_EvictControl(m_impl->m_ctx,
                              ESYS_TR_RH_OWNER /*TODO: hierarchy*/,
                              handles.transient_handle(),
                              sessions[0],
                              sessions[1],
                              sessions[2],
                              0,
                              &no_new_handle));
   BOTAN_ASSERT(no_new_handle == ESYS_TR_NONE, "When deleting a key, no new handle is returned");

   // 2. The persistent key was deleted and the transient key was flushed by
   //    Esys_EvictControl().
   handles._disengage();
}

Context::~Context() {
   if(m_impl) {
      Esys_Finalize(&m_impl->m_ctx);
      Tss2_TctiLdr_Finalize(&m_impl->m_tcti_ctx);
   }
}

}  // namespace Botan::TPM2
