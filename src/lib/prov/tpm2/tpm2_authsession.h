/*
* TPM 2 Auth Session Wrapper
* (C) 2024 Jack Lloyd
* (C) 2024 René Meusel, Amos Treiber - Rohde & Schwarz Cybersecurity GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/
#ifndef BOTAN_TPM2_AUTHSESSION_H_
#define BOTAN_TPM2_AUTHSESSION_H_

#include <botan/tpm2.h>

#include <tss2/tss2_esys.h>

namespace Botan {

class TPM2_AuthSession {
      //Always establishes an HMAC session. Shall only be used within TPM2_Context
      // TODO: Constructors

   public:
      /**
         * @param ctx  The TPM2_Context to use for the session
         */
      TPM2_AuthSession(std::shared_ptr<TPM2_Context> ctx);

      ~TPM2_AuthSession();

      ESYS_TR session() const { return m_session; }

   private:
      std::shared_ptr<TPM2_Context> m_ctx;
      ESYS_TR m_session;
};

}  // namespace Botan

#endif
