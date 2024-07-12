/*
* TPM 2 Auth Session Wrapper
* (C) 2024 Jack Lloyd
* (C) 2024 René Meusel, Amos Treiber - Rohde & Schwarz Cybersecurity GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/tpm2_authsession.h>
#include <botan/internal/tpm2_util.h>

#include <string>

namespace Botan {

TPM2_AuthSession::TPM2_AuthSession(std::shared_ptr<TPM2_Context> ctx, std::string_view spk_handle) :
      m_ctx(std::move(ctx)) {
   // First obtain the spk (storage primary key) with handle spk_handle
   check_tss2_rc("Esys_TR_FromTPMPublic",
                 Esys_TR_FromTPMPublic(inner(m_ctx),
                                       std::stoul(spk_handle.data(), nullptr, 0) /* TODO: use uint32_t*/,
                                       ESYS_TR_NONE /*TODO: Use of a session is already recommended here?*/,
                                       ESYS_TR_NONE,
                                       ESYS_TR_NONE,
                                       &m_spk_handle));

   // TODO: SPK from another source / verify certificate / password-protected

   // Then, start an authorization session
   const TPMT_SYM_DEF auth_sym = {
      //TODO: Sensible parameters
      .algorithm = TPM2_ALG_AES,
      .keyBits = {.aes = 256},
      .mode = {.aes = TPM2_ALG_CFB},
   };
   const TPMI_ALG_HASH auth_hash = TPM2_ALG_SHA256;  //TODO: Sensible parameters
   check_tss2_rc(
      "Esys_StartAuthSession",
      Esys_StartAuthSession(inner(m_ctx),
                            m_spk_handle /*used to encrypt a random salt. TODO: Where to PK bytes come from?*/,
                            m_spk_handle /*bind*/,
                            ESYS_TR_NONE,
                            ESYS_TR_NONE,
                            ESYS_TR_NONE,
                            nullptr /*NonceCaller generated automatically*/,
                            TPM2_SE_HMAC,
                            &auth_sym,
                            auth_hash,
                            &m_session));

   // Set the session attributes. TODO: Different keys require different attributes...
   const TPMA_SESSION session_attributes =
      TPMA_SESSION_CONTINUESESSION | TPMA_SESSION_AUDIT; /* to sign and for Gen/Stir random*/

   check_tss2_rc("Esys_TRSess_SetAttributes",
                 Esys_TRSess_SetAttributes(inner(m_ctx), m_session, session_attributes, 0xFF));
}

TPM2_AuthSession::~TPM2_AuthSession() {
   //TODO: Somehow we leak and get full of transient objects with the session...
   if(m_spk_handle != ESYS_TR_NONE) {
      check_tss2_rc("Esys_FlushContext", Esys_FlushContext(inner(m_ctx), m_spk_handle));
      m_spk_handle = ESYS_TR_NONE;
   }
   if(m_session != ESYS_TR_NONE) {
      check_tss2_rc("Esys_FlushContext", Esys_FlushContext(inner(m_ctx), m_session));
      m_session = ESYS_TR_NONE;
   }
}
}  // namespace Botan
