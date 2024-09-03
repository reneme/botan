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

namespace {

using SessionAttributesWrapper =
   AttributeWrapper<TPMA_OBJECT,
                    SessionAttributes,
                    std::pair{&SessionAttributes::continue_session, TPMA_SESSION_CONTINUESESSION},
                    std::pair{&SessionAttributes::decrypt, TPMA_SESSION_DECRYPT},
                    std::pair{&SessionAttributes::encrypt, TPMA_SESSION_ENCRYPT},
                    std::pair{&SessionAttributes::audit, TPMA_SESSION_AUDIT}>;

}  // namespace

SessionAttributes SessionAttributes::read(TPMA_SESSION attributes) {
   return SessionAttributesWrapper::read(attributes);
}

TPMA_SESSION SessionAttributes::render(SessionAttributes attributes) {
   return SessionAttributesWrapper::render(attributes);
}

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
   return SessionAttributes::read(attrs);
}

void Session::set_attributes(SessionAttributes attributes) {
   check_rc("Esys_TRSess_SetAttributes",
            Esys_TRSess_SetAttributes(
               inner(m_session.context()), m_session.transient_handle(), SessionAttributes::render(attributes), 0xFF));
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
