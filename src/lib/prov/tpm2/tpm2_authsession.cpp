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

TPM2_AuthSession::TPM2_AuthSession(std::shared_ptr<TPM2_Context> ctx) : m_ctx(std::move(ctx)) {
   // Start an authorization session
   const TPMT_SYM_DEF auth_sym = {.algorithm = TPM2_ALG_AES, .keyBits = {.aes = 128}, .mode = {.aes = TPM2_ALG_CFB}};
   const TPMI_ALG_HASH auth_hash = TPM2_ALG_SHA256;  //TODO: Sensible parameters
   check_tss2_rc("Esys_StartAuthSession",
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

   TPMA_SESSION sessionAttributes = TPMA_SESSION_CONTINUESESSION | TPMA_SESSION_DECRYPT | TPMA_SESSION_ENCRYPT;
   check_tss2_rc("Esys_TRSess_SetAttributes",
                 Esys_TRSess_SetAttributes(inner(m_ctx), m_session, sessionAttributes, 0xFF));
}

TPM2_AuthSession::~TPM2_AuthSession() {
   if(m_session != ESYS_TR_NONE) {
      check_tss2_rc("Esys_FlushContext", Esys_FlushContext(inner(m_ctx), m_session));
      m_session = ESYS_TR_NONE;
   }
}
}  // namespace Botan
