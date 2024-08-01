/*
* TPM 2 Auth Session Wrapper
* (C) 2024 Jack Lloyd
* (C) 2024 René Meusel, Amos Treiber - Rohde & Schwarz Cybersecurity GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/
#ifndef BOTAN_TPM2_SESSION_H_
#define BOTAN_TPM2_SESSION_H_

#include <botan/tpm2.h>

#include <botan/secmem.h>
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

class Session {
   public:
      static std::shared_ptr<Session> unauthenticated_session(const std::shared_ptr<Context>& ctx);

   public:
      uint32_t handle() const { return m_session.transient_handle(); }

      SessionAttributes attributes() const;
      void set_attributes(SessionAttributes attributes);

      secure_vector<uint8_t> tpm_nonce() const;

   private:
      Session(Object session, SessionAttributes attributes);

   private:
      Object m_session;
};

}  // namespace Botan::TPM2

#endif
