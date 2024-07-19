/*
* TPM 2 interface
* (C) 2024 Jack Lloyd
* (C) 2024 René Meusel, Amos Treiber - Rohde & Schwarz Cybersecurity GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/tpm2.h>

#include <botan/internal/fmt.h>
#include <botan/internal/loadstor.h>
#include <botan/internal/stl_util.h>
#include <botan/internal/tpm2_authsession.h>
#include <botan/internal/tpm2_util.h>

#include <algorithm>
#include <array>
#include <tss2/tss2_esys.h>
#include <tss2/tss2_tcti.h>
#include <tss2/tss2_tctildr.h>

namespace Botan {

TPM2_Error::TPM2_Error(std::string_view location, uint32_t rc) :
      Exception(fmt("TPM2 Exception in {}: Code {} ({})", location, rc, Tss2_RC_Decode(rc))), m_rc(rc) {}

std::string TPM2_Error::error_message() const {
   return Tss2_RC_Decode(m_rc);
}

struct TPM2_Context::Impl {
      TSS2_TCTI_CONTEXT* m_tcti_ctx;
      ESYS_CONTEXT* m_ctx;
};

std::shared_ptr<TPM2_Context> TPM2_Context::create(std::optional<std::string> tcti_nameconf) {
   const auto tcti_nameconf_ptr = [&]() -> const char* {
      if(tcti_nameconf.has_value()) {
         return tcti_nameconf->c_str();
      } else {
         return nullptr;
      }
   }();

   // We cannot std::make_shared as the constructor is private
   auto ctx = std::shared_ptr<TPM2_Context>(new TPM2_Context(tcti_nameconf_ptr));

   auto auth_session = std::make_unique<TPM2_AuthSession>(ctx, "0x81000001" /*SRK*/);
   ctx->set_session(auth_session);

   return ctx;
}

TPM2_Context::TPM2_Context(const char* tcti_nameconf) : m_impl(std::make_unique<Impl>()) {
   check_tss2_rc("TCTI Initialization", Tss2_TctiLdr_Initialize(tcti_nameconf, &m_impl->m_tcti_ctx));
   check_tss2_rc("TPM2 Initialization", Esys_Initialize(&m_impl->m_ctx, m_impl->m_tcti_ctx, nullptr /* ABI version */));
}

void TPM2_Context::set_session(std::unique_ptr<TPM2_AuthSession>& auth_session) {
   m_auth_session = std::move(auth_session);
}

void* TPM2_Context::inner_context_object() {
   return m_impl->m_ctx;
}

uint32_t TPM2_Context::inner_session_object() {
   return m_auth_session->session();
}

uint32_t TPM2_Context::spk_handle() const {
   return m_auth_session->spk_handle();
}

std::string TPM2_Context::vendor() const {
   std::array<TPM2_PT, 4> properties = {
      TPM2_PT_VENDOR_STRING_1, TPM2_PT_VENDOR_STRING_2, TPM2_PT_VENDOR_STRING_3, TPM2_PT_VENDOR_STRING_4};
   std::array<uint8_t, properties.size() * sizeof(TPM2_PT) + 1 /* ensure zero-termination */> vendor_string{};

   BufferStuffer bs(vendor_string);

   // The vendor name is transported in several uint32_t fields that are
   // loaded as big-endian bytes and concatenated to form the vendor string.
   for(auto prop : properties) {
      TPMI_YES_NO more_data;
      TPMS_CAPABILITY_DATA* capability_data;

      check_tss2_rc("Esys_GetCapability",
                    Esys_GetCapability(m_impl->m_ctx,
                                       ESYS_TR_NONE,
                                       ESYS_TR_NONE,
                                       ESYS_TR_NONE,
                                       TPM2_CAP_TPM_PROPERTIES,
                                       prop,
                                       1,
                                       &more_data,
                                       &capability_data));

      BOTAN_STATE_CHECK(capability_data->capability == TPM2_CAP_TPM_PROPERTIES &&
                        capability_data->data.tpmProperties.count > 0);
      bs.append(store_be(capability_data->data.tpmProperties.tpmProperty[0].value));
      Esys_Free(capability_data);
   }

   BOTAN_ASSERT_NOMSG(bs.remaining_capacity() == 1);  // the ensured zero-termination
   return std::string(reinterpret_cast<const char*>(vendor_string.data()));
}

std::vector<uint32_t> TPM2_Context::persistent_handles() const {
   std::vector<uint32_t> handles;

   TPMI_YES_NO more_data;
   TPMS_CAPABILITY_DATA* capability_data = nullptr;

   check_tss2_rc("Esys_GetCapability",
                 Esys_GetCapability(m_impl->m_ctx,
                                    ESYS_TR_NONE,
                                    ESYS_TR_NONE,
                                    ESYS_TR_NONE,
                                    TPM2_CAP_HANDLES,
                                    TPM2_PERSISTENT_FIRST,
                                    TPM2_MAX_CAP_HANDLES,
                                    &more_data,
                                    &capability_data));

   for(size_t i = 0; i < capability_data->data.handles.count; i++) {
      handles.push_back(capability_data->data.handles.handle[i]);
   }
   Esys_Free(capability_data);
   return handles;
}

bool TPM2_Context::in_persistent_handles(uint32_t persistent_handle) const {
   auto persistent_handles = this->persistent_handles();
   return std::find(persistent_handles.begin(), persistent_handles.end(), persistent_handle) !=
          persistent_handles.end();
}

TPM2_Context::~TPM2_Context() {
   Esys_Finalize(&m_impl->m_ctx);
   Tss2_TctiLdr_Finalize(&m_impl->m_tcti_ctx);
}

}  // namespace Botan
