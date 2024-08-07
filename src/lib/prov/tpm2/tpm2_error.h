/*
* TPM 2 error handling
* (C) 2024 Jack Lloyd
* (C) 2024 René Meusel, Amos Treiber - Rohde & Schwarz Cybersecurity GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_TPM2_ERROR_H_
#define BOTAN_TPM2_ERROR_H_

#include <botan/exceptn.h>

namespace Botan::TPM2 {

uint32_t get_raw_rc(uint32_t rc);

class BOTAN_PUBLIC_API(3, 6) Error final : public Exception {
   public:
      Error(std::string_view location, uint32_t rc);

      ErrorType error_type() const noexcept override { return ErrorType::TPMError; }

      uint32_t code() const { return m_rc; }

      int error_code() const noexcept override {
         // RC is uint32 but the maximum value is within int32 range as per tss2_common.h
         return static_cast<int>(m_rc);
      }

      std::string error_message() const;

   private:
      uint32_t m_rc;
};

}  // namespace Botan::TPM2

#endif
