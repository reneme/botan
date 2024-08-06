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

#include <botan/internal/fmt.h>

namespace Botan::TPM2 {

/**
 * @returns a TPMI_ALG_HASH value if the @p hash_name is known,
 *          otherwise std::nullopt
 */

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

/**
 * @returns a Botan hash name string if the @p hash_id value is known,
 *          otherwise std::nullopt
 */
[[nodiscard]] constexpr std::optional<std::string> hash_algo_tss2_to_botan(TPM2_ALG_ID hash_id) noexcept {
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
      default:  // TPM2_ALG_ID is not an enum
         return std::nullopt;
   }
}

/**
 * @returns a Botan cipher mode name string if the @p cipher_id, @p key_bits and
 *          @p mode_name are known, otherwise std::nullopt
 */
[[nodiscard]] constexpr std::optional<std::string> cipher_mode_tss2_to_botan(TPM2_ALG_ID cipher_id,
                                                                             TPM2_KEY_BITS key_bits,
                                                                             TPM2_ALG_ID mode_id) noexcept {
   const auto cipher_name = [&]() -> std::optional<std::string> {
      if(cipher_id == TPM2_ALG_AES) {
         if(key_bits == 128) {
            return "AES-128";
         } else if(key_bits == 192) {
            return "AES-192";
         } else if(key_bits == 256) {
            return "AES-256";
         }
      } else if(cipher_id == TPM2_ALG_SM4) {
         if(key_bits == 128) {
            return "SM4";
         }
      } else if(cipher_id == TPM2_ALG_CAMELLIA) {
         if(key_bits == 128) {
            return "Camellia-128";
         } else if(key_bits == 192) {
            return "Camellia-192";
         } else if(key_bits == 256) {
            return "Camellia-256";
         }
      } else if(cipher_id == TPM2_ALG_TDES) {
         return "3DES";
      }

      return std::nullopt;
   }();

   const auto mode_name = [&]() -> std::optional<std::string> {
      switch(mode_id) {
         case TPM2_ALG_CFB:
            return "CFB";
         case TPM2_ALG_CBC:
            return "CBC";
         case TPM2_ALG_ECB:
            return "ECB";
         case TPM2_ALG_OFB:
            return "OFB";
         case TPM2_ALG_CTR:
            return "CTR";
         default:  // TPM2_ALG_ID is not an enum
            return std::nullopt;
      }
   }();

   if(!cipher_name || !mode_name) {
      return std::nullopt;
   }

   return Botan::fmt("{}({})", mode_name.value(), cipher_name.value());
}

}  // namespace Botan::TPM2

#endif
