/*
* TPM 2 Auth Session Wrapper
* (C) 2024 Jack Lloyd
* (C) 2024 René Meusel, Amos Treiber - Rohde & Schwarz Cybersecurity GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/
#ifndef BOTAN_TPM2_SESSION_H_
#define BOTAN_TPM2_SESSION_H_

#include <botan/secmem.h>
#include <botan/tpm2_context.h>
#include <botan/tpm2_object.h>

#include <array>
#include <memory>

namespace Botan::TPM2 {

using TPMA_SESSION = uint8_t;

/**
 * See TPM 2.0 Part 2, Section 8.4
 */

struct SessionAttributes {
      static SessionAttributes read(TPMA_SESSION attributes);
      static TPMA_SESSION render(SessionAttributes attributes);

      /// The session may or may not remain active after the successful completion of any command.
      bool continue_session = false;

      /// Indicates that a command should only be executed if the session is exclusive.
      bool audit_exclusive = false;

      /// Indicates that the audit digest should be initialized and exclusive status of the session SET
      bool audit_reset = false;

      /// Indicates that the first parameter of the command is to be decrypted by the TPM
      bool decrypt = false;

      /// Indicates that the first parameter of a command's response is to be encrypted by the TPM
      bool encrypt = false;

      /// Indicates that the session is fused for audit and that audit_exclusive and audit_reset have meaning
      bool audit = false;
};

class Session;
class PrivateKey;

namespace detail {

class BOTAN_UNSTABLE_API SessionHandle final {
   public:
      SessionHandle() = default;

      SessionHandle(const SessionHandle&) = delete;
      SessionHandle& operator=(const SessionHandle&) = delete;
      SessionHandle(SessionHandle&&) = delete;
      SessionHandle& operator=(SessionHandle&&) = delete;

      ~SessionHandle();
      [[nodiscard]] operator uint32_t() && noexcept;

   private:
      friend class Botan::TPM2::Session;

      SessionHandle(Session& session);

   private:
      std::optional<std::reference_wrapper<Session>> m_session;
      SessionAttributes m_original_attributes;
};

}  // namespace detail

class BOTAN_PUBLIC_API(3, 6) Session {
   public:
      static std::shared_ptr<Session> unauthenticated_session(const std::shared_ptr<Context>& ctx);
      static std::shared_ptr<Session> authenticated_session(const std::shared_ptr<Context>& ctx,
                                                            const TPM2::PrivateKey& tpm_key);

   public:
      [[nodiscard]] detail::SessionHandle handle() { return *this; }

      SessionAttributes attributes() const;
      void set_attributes(SessionAttributes attributes);

      secure_vector<uint8_t> tpm_nonce() const;

   private:
      friend class detail::SessionHandle;

      Session(Object session, SessionAttributes attributes);

      uint32_t transient_handle() const noexcept { return m_session.transient_handle(); }

   private:
      Object m_session;
};

inline detail::SessionHandle::~SessionHandle() {
   if(m_session) {
      m_session->get().set_attributes(m_original_attributes);
   }
}

inline detail::SessionHandle::SessionHandle(Session& session) :
      m_session(session), m_original_attributes(session.attributes()) {}

class SessionBundle {
   public:
      SessionBundle(std::shared_ptr<Session> s1 = nullptr,
                    std::shared_ptr<Session> s2 = nullptr,
                    std::shared_ptr<Session> s3 = nullptr) :
            m_sessions({std::move(s1), std::move(s2), std::move(s3)}) {}

      [[nodiscard]] detail::SessionHandle operator[](size_t i) const noexcept {
         if(m_sessions[i] == nullptr) {
            return {};
         } else {
            return m_sessions[i]->handle();
         }
      }

   private:
      std::array<std::shared_ptr<Session>, 3> m_sessions;
};

}  // namespace Botan::TPM2

#endif
