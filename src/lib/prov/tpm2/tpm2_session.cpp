/*
* TPM 2 Auth Session Wrapper
* (C) 2024 Jack Lloyd
* (C) 2024 René Meusel, Amos Treiber - Rohde & Schwarz Cybersecurity GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/tpm2_session.h>

#include <botan/tpm2_key.h>

#include <botan/internal/stl_util.h>
#include <botan/internal/tpm2_util.h>

namespace Botan::TPM2 {

// static
std::shared_ptr<Session> Session::unauthenticated_session(const std::shared_ptr<Context>& ctx) {
   Object session(ctx);

   // TODO: Perhaps we want to make this configurable.
   //       I could imagine that there's a synergy with the key-generation
   //       handling (see rsa.cpp), when building a wrapper for that.
   //
   //       Given that we want to achieve a certification for our implementation,
   //       is is probably helpful to give the application documentable control
   //       over these parameters.
   //
   //       Its very likely a good idea to have a convenient and sane default
   //       and build the API in a way that other users don't have to worry.
   const TPMT_SYM_DEF auth_sym = {
      .algorithm = TPM2_ALG_AES,
      .keyBits = {.aes = 128},
      .mode = {.aes = TPM2_ALG_CFB},
   };

   check_rc("Esys_StartSession",
            Esys_StartAuthSession(inner(ctx),
                                  ESYS_TR_NONE,
                                  ESYS_TR_NONE,
                                  ESYS_TR_NONE,
                                  ESYS_TR_NONE,
                                  ESYS_TR_NONE,
                                  nullptr /*NonceCaller generated automatically*/,
                                  TPM2_SE_HMAC,
                                  &auth_sym,
                                  TPM2_ALG_SHA256,
                                  out_transient_handle(session)));

   return std::shared_ptr<Session>(new Session(std::move(session),
                                               {
                                                  .continue_session = true,
                                                  .decrypt = true,
                                                  .encrypt = true,
                                                  .audit = false,
                                               }));
}

std::shared_ptr<Session> Session::authenticated_session(const std::shared_ptr<Context>& ctx,
                                                        const TPM2::PrivateKey& tpm_key) {
   Object session(ctx);

   // TODO: Probably should be configurable.
   //       See unauthenticated_session for more details.
   const TPMT_SYM_DEF auth_sym = {
      .algorithm = TPM2_ALG_AES,
      .keyBits = {.aes = 256},
      .mode = {.aes = TPM2_ALG_CFB},
   };

   check_rc("Esys_StartSession",
            Esys_StartAuthSession(inner(ctx),
                                  tpm_key.handles().transient_handle(),
                                  tpm_key.handles().transient_handle(),
                                  ESYS_TR_NONE,
                                  ESYS_TR_NONE,
                                  ESYS_TR_NONE,
                                  nullptr /*NonceCaller generated automatically*/,
                                  TPM2_SE_HMAC,
                                  &auth_sym,
                                  TPM2_ALG_SHA256,
                                  out_transient_handle(session)));

   return std::shared_ptr<Session>(new Session(std::move(session),
                                               {
                                                  .continue_session = true,
                                                  .decrypt = true,
                                                  .encrypt = true,
                                                  .audit = false,
                                               }));
}

Session::Session(Object session, SessionAttributes attributes) : m_session(std::move(session)) {
   set_attributes(attributes);
}

SessionAttributes Session::attributes() const {
   TPMA_SESSION attrs;
   check_rc("Esys_TRSess_GetAttributes",
            Esys_TRSess_GetAttributes(inner(m_session.context()), m_session.transient_handle(), &attrs));
   return {
      .continue_session = (attrs & TPMA_SESSION_CONTINUESESSION) != 0,
      .decrypt = (attrs & TPMA_SESSION_DECRYPT) != 0,
      .encrypt = (attrs & TPMA_SESSION_ENCRYPT) != 0,
      .audit = (attrs & TPMA_SESSION_AUDIT) != 0,
   };
}

void Session::set_attributes(SessionAttributes attributes) {
   auto expand = [](bool flag) -> TPMA_SESSION {
      static_assert(std::is_unsigned_v<TPMA_SESSION>);
      return flag ? TPMA_SESSION(-1) : TPMA_SESSION(0);
   };

   TPMA_SESSION attrs = 0;
   attrs |= TPMA_SESSION_CONTINUESESSION & expand(attributes.continue_session);
   attrs |= TPMA_SESSION_DECRYPT & expand(attributes.decrypt);
   attrs |= TPMA_SESSION_ENCRYPT & expand(attributes.encrypt);
   attrs |= TPMA_SESSION_AUDIT & expand(attributes.audit);

   check_rc("Esys_TRSess_SetAttributes",
            Esys_TRSess_SetAttributes(inner(m_session.context()), m_session.transient_handle(), attrs, 0xFF));
}

secure_vector<uint8_t> Session::tpm_nonce() const {
   unique_esys_ptr<TPM2B_NONCE> nonce;
   check_rc("Esys_TRSess_GetNonceTPM",
            Esys_TRSess_GetNonceTPM(inner(m_session.context()), m_session.transient_handle(), out_ptr(nonce)));
   return copy_into<secure_vector<uint8_t>>(*nonce);
}

[[nodiscard]] detail::SessionHandle::operator uint32_t() && noexcept {
   if(m_session) {
      return m_session->get().transient_handle();
   } else {
      return ESYS_TR_NONE;
   }
}

}  // namespace Botan::TPM2
