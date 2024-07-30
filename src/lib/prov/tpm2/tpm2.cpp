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

namespace Botan::TPM2 {

Error::Error(std::string_view location, uint32_t rc) :
      Exception(fmt("TPM2 Exception in {}: Code {} ({})", location, rc, Tss2_RC_Decode(rc))), m_rc(rc) {}

std::string Error::error_message() const {
   return Tss2_RC_Decode(m_rc);
}

struct Context::Impl {
      TSS2_TCTI_CONTEXT* m_tcti_ctx;
      ESYS_CONTEXT* m_ctx;
};

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

Context::Context(const char* tcti_nameconf) :
      m_impl(std::make_unique<Impl>()), m_session_handles{ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE} {
   check_rc("TCTI Initialization", Tss2_TctiLdr_Initialize(tcti_nameconf, &m_impl->m_tcti_ctx));
   check_rc("TPM2 Initialization", Esys_Initialize(&m_impl->m_ctx, m_impl->m_tcti_ctx, nullptr /* ABI version */));
}

Context::Context(const char* tcti_name, const char* tcti_conf) :
      m_impl(std::make_unique<Impl>()), m_session_handles{ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE} {
   check_rc("TCTI Initialization", Tss2_TctiLdr_Initialize_Ex(tcti_name, tcti_conf, &m_impl->m_tcti_ctx));
   check_rc("TPM2 Initialization", Esys_Initialize(&m_impl->m_ctx, m_impl->m_tcti_ctx, nullptr /* ABI version */));
}

void Context::set_sessions(std::optional<uint32_t> session1,
                           std::optional<uint32_t> session2,
                           std::optional<uint32_t> session3) {
   auto set_session = [this](auto& session, size_t idx) {
      if(session.has_value()) {
         m_session_handles[idx] = session.value();
      }
   };
   set_session(session1, 0);
   set_session(session2, 1);
   set_session(session3, 2);
}

void* Context::inner_context_object() {
   return m_impl->m_ctx;
}

std::string Context::vendor() const {
   std::array<TPM2_PT, 4> properties = {
      TPM2_PT_VENDOR_STRING_1, TPM2_PT_VENDOR_STRING_2, TPM2_PT_VENDOR_STRING_3, TPM2_PT_VENDOR_STRING_4};
   std::array<uint8_t, properties.size() * sizeof(TPM2_PT) + 1 /* ensure zero-termination */> vendor_string{};

   BufferStuffer bs(vendor_string);

   // The vendor name is transported in several uint32_t fields that are
   // loaded as big-endian bytes and concatenated to form the vendor string.
   for(auto prop : properties) {
      TPMI_YES_NO more_data;
      unique_esys_ptr<TPMS_CAPABILITY_DATA> capability_data;

      check_rc("Esys_GetCapability",
               Esys_GetCapability(m_impl->m_ctx,
                                  ESYS_TR_NONE,
                                  ESYS_TR_NONE,
                                  ESYS_TR_NONE,
                                  TPM2_CAP_TPM_PROPERTIES,
                                  prop,
                                  1,
                                  &more_data,
                                  out_ptr(capability_data)));

      BOTAN_STATE_CHECK(capability_data->capability == TPM2_CAP_TPM_PROPERTIES &&
                        capability_data->data.tpmProperties.count > 0);
      bs.append(store_be(capability_data->data.tpmProperties.tpmProperty[0].value));
   }

   BOTAN_ASSERT_NOMSG(bs.remaining_capacity() == 1);  // the ensured zero-termination
   return std::string(reinterpret_cast<const char*>(vendor_string.data()));
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
   Esys_Finalize(&m_impl->m_ctx);
   Tss2_TctiLdr_Finalize(&m_impl->m_tcti_ctx);
}

}  // namespace Botan::TPM2
