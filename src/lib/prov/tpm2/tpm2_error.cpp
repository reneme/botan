/*
* TPM 2 error handling
* (C) 2024 Jack Lloyd
* (C) 2024 René Meusel, Amos Treiber - Rohde & Schwarz Cybersecurity GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/tpm2_error.h>

#include <botan/internal/fmt.h>

#include <tss2/tss2_rc.h>

namespace Botan::TPM2 {

Error::Error(std::string_view location, uint32_t rc) :
      Exception(fmt("TPM2 Exception in {}: Code {} ({})", location, rc, Tss2_RC_Decode(rc))), m_rc(rc) {}

std::string Error::error_message() const {
   return Tss2_RC_Decode(m_rc);
}

}  // namespace Botan::TPM2
