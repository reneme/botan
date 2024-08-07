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
   BOTAN_ASSERT_NOMSG(capability_data->capability == capability);
   BOTAN_ASSERT_NOMSG(capability_data->data.tpmProperties.count == property_count);
   BOTAN_ASSERT_NOMSG(capability_data->data.tpmProperties.tpmProperty[0].property == property);

   return capability_data->data.tpmProperties.tpmProperty[0].value;
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
   // TODO: remove the SRK address magic number
   // TODO: allow loading ECC-based keys as well
   //       (probably by providing a generic 'from_persistent' function that
   //       detects the key type automatically and returns a suitable object)
   return RSA_PrivateKey::from_persistent(shared_from_this(), 0x81000001 /*SRK location*/, auth_value, sessions);
}

std::vector<uint32_t> Context::persistent_handles() const {
   TPMI_YES_NO more_data;
   unique_esys_ptr<TPMS_CAPABILITY_DATA> capability_data;

   check_rc("Esys_GetCapability",
            Esys_GetCapability(m_impl->m_ctx,
                               ESYS_TR_NONE,
                               ESYS_TR_NONE,
                               ESYS_TR_NONE,
                               TPM2_CAP_HANDLES,
                               TPM2_PERSISTENT_FIRST,
                               TPM2_MAX_CAP_HANDLES,
                               &more_data,
                               out_ptr(capability_data)));

   // TODO: Check if we have `more_data`

   return {capability_data->data.handles.handle,
           capability_data->data.handles.handle + capability_data->data.handles.count};
}

bool Context::in_persistent_handles(uint32_t persistent_handle) const {
   auto persistent_handles = this->persistent_handles();
   return std::find(persistent_handles.begin(), persistent_handles.end(), persistent_handle) !=
          persistent_handles.end();
}

Context::~Context() {
   if(m_impl) {
      Esys_Finalize(&m_impl->m_ctx);
      Tss2_TctiLdr_Finalize(&m_impl->m_tcti_ctx);
   }
}

}  // namespace Botan::TPM2
