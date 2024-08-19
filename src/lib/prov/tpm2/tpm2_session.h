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

struct SessionAttributes {
      bool continue_session;
      bool decrypt;
      bool encrypt;
      bool audit;
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
