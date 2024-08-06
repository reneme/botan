/*
* TPM 2 algorithm mappings
* (C) 2024 Jack Lloyd
* (C) 2024 René Meusel, Amos Treiber - Rohde & Schwarz Cybersecurity GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_TPM2_ALGORITHM_MAPPINGS_H_
#define BOTAN_TPM2_ALGORITHM_MAPPINGS_H_

#include <optional>
#include <string>
#include <string_view>

#include <tss2/tss2_tpm2_types.h>

namespace Botan::TPM2 {

[[nodiscard]] constexpr std::optional<TPMI_ALG_HASH> hash_algo_botan_to_tss2(std::string_view hash_name) noexcept {
   if(hash_name == "SHA-1") {
      return TPM2_ALG_SHA1;
   } else if(hash_name == "SHA-256") {
      return TPM2_ALG_SHA256;
   } else if(hash_name == "SHA-384") {
      return TPM2_ALG_SHA384;
   } else if(hash_name == "SHA-512") {
      return TPM2_ALG_SHA512;
   } else if(hash_name == "SHA-3(256)") {
      return TPM2_ALG_SHA3_256;
   } else if(hash_name == "SHA-3(384)") {
      return TPM2_ALG_SHA3_384;
   } else if(hash_name == "SHA-3(512)") {
      return TPM2_ALG_SHA3_512;
   } else {
      return std::nullopt;
   }
}

[[nodiscard]] constexpr std::optional<std::string> hash_algo_tss2_to_botan(TPMI_ALG_HASH hash_id) noexcept {
   switch(hash_id) {
      case TPM2_ALG_SHA1:
         return "SHA-1";
      case TPM2_ALG_SHA256:
         return "SHA-256";
      case TPM2_ALG_SHA384:
         return "SHA-384";
      case TPM2_ALG_SHA512:
         return "SHA-512";
      case TPM2_ALG_SHA3_256:
         return "SHA-3(256)";
      case TPM2_ALG_SHA3_384:
         return "SHA-3(384)";
      case TPM2_ALG_SHA3_512:
         return "SHA-3(512)";
      default:  // TPMI_ALG_HASH is not an enum
         return std::nullopt;
   }
}

}  // namespace Botan::TPM2

#endif
