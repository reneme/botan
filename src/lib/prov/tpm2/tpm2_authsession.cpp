/*
* TPM 2 Auth Session Wrapper
* (C) 2024 Jack Lloyd
* (C) 2024 René Meusel, Amos Treiber - Rohde & Schwarz Cybersecurity GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/tpm2_authsession.h>

#include <botan/internal/stl_util.h>
#include <botan/internal/tpm2_util.h>

namespace Botan::TPM2 {

AuthSession::AuthSession(std::shared_ptr<Context> ctx) : m_ctx(std::move(ctx)) {
   // Start an authorization session
   const TPMT_SYM_DEF auth_sym = {.algorithm = TPM2_ALG_AES, .keyBits = {.aes = 128}, .mode = {.aes = TPM2_ALG_CFB}};
   const TPMI_ALG_HASH auth_hash = TPM2_ALG_SHA256;  //TODO: Sensible parameters
   check_rc("Esys_StartAuthSession",
            Esys_StartAuthSession(inner(m_ctx),
                                  ESYS_TR_NONE,
                                  ESYS_TR_NONE,
                                  ESYS_TR_NONE,
                                  ESYS_TR_NONE,
                                  ESYS_TR_NONE,
                                  nullptr /*NonceCaller generated automatically*/,
                                  TPM2_SE_HMAC,
                                  &auth_sym,
                                  auth_hash,
                                  &m_session));

   set_attributes({
      .continue_session = true,
      .decrypt = true,
      .encrypt = true,
      .audit = false,
   });
}

AuthSession::~AuthSession() {
   if(m_session != ESYS_TR_NONE) {
      check_rc("Esys_FlushContext", Esys_FlushContext(inner(m_ctx), m_session));
      m_session = ESYS_TR_NONE;
   }
}

SessionAttributes AuthSession::attributes() const {
   TPMA_SESSION attrs;
   check_rc("Esys_TRSess_GetAttributes", Esys_TRSess_GetAttributes(inner(m_ctx), m_session, &attrs));
   return {.continue_session = (attrs & TPMA_SESSION_CONTINUESESSION) != 0,
           .decrypt = (attrs & TPMA_SESSION_DECRYPT) != 0,
           .encrypt = (attrs & TPMA_SESSION_ENCRYPT) != 0,
           .audit = (attrs & TPMA_SESSION_AUDIT) != 0};
}

void AuthSession::set_attributes(SessionAttributes attributes) {
   auto expand = [](bool flag) -> TPMA_SESSION {
      static_assert(std::is_unsigned_v<TPMA_SESSION>);
      return flag ? TPMA_SESSION(-1) : TPMA_SESSION(0);
   };

   TPMA_SESSION attrs = 0;
   attrs |= TPMA_SESSION_CONTINUESESSION & expand(attributes.continue_session);
   attrs |= TPMA_SESSION_DECRYPT & expand(attributes.decrypt);
   attrs |= TPMA_SESSION_ENCRYPT & expand(attributes.encrypt);
   attrs |= TPMA_SESSION_AUDIT & expand(attributes.audit);

   check_rc("Esys_TRSess_SetAttributes", Esys_TRSess_SetAttributes(inner(m_ctx), m_session, attrs, 0xFF));
}

secure_vector<uint8_t> AuthSession::tpm_nonce() const {
   unique_esys_ptr<TPM2B_NONCE> nonce;
   check_rc("Esys_TRSess_GetNonceTPM", Esys_TRSess_GetNonceTPM(inner(m_ctx), m_session, out_ptr(nonce)));
   return copy_into<secure_vector<uint8_t>>(*nonce);
}

}  // namespace Botan::TPM2
