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

#include <botan/exceptn.h>

#include <botan/internal/fmt.h>
#include <botan/internal/scan_name.h>

namespace Botan::TPM2 {

/**
 * @returns a TPMI_ALG_HASH value if the @p hash_name is known,
 *          otherwise std::nullopt
 */

[[nodiscard]] inline std::optional<TPMI_ALG_HASH> hash_algo_botan_to_tss2(std::string_view hash_name) noexcept {
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
 * @returns a TPMI_ALG_HASH value if the @p hash_name is known,
 *         otherwise throws Lookup_Error
  */
[[nodiscard]] inline TPMI_ALG_HASH get_tpm2_hash_type(std::string_view hash_name) {
   if(auto hash_id = hash_algo_botan_to_tss2(hash_name)) {
      return hash_id.value();
   }

   throw Lookup_Error("TPM 2.0 Hash", hash_name);
}

/**
 * @returns a Botan hash name string if the @p hash_id value is known,
 *          otherwise std::nullopt
 */
[[nodiscard]] inline std::optional<std::string> hash_algo_tss2_to_botan(TPMI_ALG_HASH hash_id) noexcept {
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

/**
 * @returns a Botan hash name string if the @p hash_id value is known,
 *          otherwise throws Invalid_State
 */
[[nodiscard]] inline std::string get_botan_hash_name(TPM2_ALG_ID hash_id) {
   if(auto hash_name = hash_algo_tss2_to_botan(hash_id)) {
      return hash_name.value();
   }

   throw Invalid_State("TPM 2.0 hash object with unexpected hash type");
}

[[nodiscard]] inline std::optional<std::string> block_cipher_tss2_to_botan(TPMI_ALG_SYM cipher_id,
                                                                           TPM2_KEY_BITS key_bits) noexcept {
   switch(cipher_id) {
      case TPM2_ALG_AES:
         if(key_bits == 128) {
            return "AES-128";
         } else if(key_bits == 192) {
            return "AES-192";
         } else if(key_bits == 256) {
            return "AES-256";
         }
         break;

      case TPM2_ALG_SM4:
         if(key_bits == 128) {
            return "SM4";
         }
         break;

      case TPM2_ALG_CAMELLIA:
         if(key_bits == 128) {
            return "Camellia-128";
         } else if(key_bits == 192) {
            return "Camellia-192";
         } else if(key_bits == 256) {
            return "Camellia-256";
         }
         break;

      case TPM2_ALG_TDES:
         return "3DES";

      default:
         break;
   }

   return std::nullopt;
}

[[nodiscard]] inline std::optional<std::pair<TPMI_ALG_SYM, TPM2_KEY_BITS>> block_cipher_botan_to_tss2(
   std::string_view cipher_name) noexcept {
   if(cipher_name == "AES-128") {
      return std::pair{TPM2_ALG_AES, 128};
   } else if(cipher_name == "AES-192") {
      return std::pair{TPM2_ALG_AES, 192};
   } else if(cipher_name == "AES-256") {
      return std::pair{TPM2_ALG_AES, 256};
   } else if(cipher_name == "SM4") {
      return std::pair{TPM2_ALG_SM4, 128};
   } else if(cipher_name == "Camellia-128") {
      return std::pair{TPM2_ALG_CAMELLIA, 128};
   } else if(cipher_name == "Camellia-192") {
      return std::pair{TPM2_ALG_CAMELLIA, 192};
   } else if(cipher_name == "Camellia-256") {
      return std::pair{TPM2_ALG_CAMELLIA, 256};
   } else if(cipher_name == "3DES") {
      return std::pair{TPM2_ALG_TDES, 168};
   } else {
      return {};
   }
}

[[nodiscard]] inline std::optional<std::string> cipher_mode_tss2_to_botan(TPMI_ALG_SYM_MODE mode_id) {
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
      default:  // TPMI_ALG_SYM_MODE is not an enum
         return std::nullopt;
   }
}

[[nodiscard]] inline std::optional<TPMI_ALG_SYM_MODE> cipher_mode_botan_to_tss2(std::string_view mode_name) noexcept {
   if(mode_name == "CFB") {
      return TPM2_ALG_CFB;
   } else if(mode_name == "CBC") {
      return TPM2_ALG_CBC;
   } else if(mode_name == "ECB") {
      return TPM2_ALG_ECB;
   } else if(mode_name == "OFB") {
      return TPM2_ALG_OFB;
   } else if(mode_name == "CTR") {
      return TPM2_ALG_CTR;
   } else {
      return std::nullopt;
   }
}

/**
 * @returns a Botan cipher mode name string if the @p cipher_id, @p key_bits and
 *          @p mode_name are known, otherwise std::nullopt
 */
[[nodiscard]] inline std::optional<std::string> cipher_tss2_to_botan(TPMT_SYM_DEF cipher_def) noexcept {
   const auto cipher_name = block_cipher_tss2_to_botan(cipher_def.algorithm, cipher_def.keyBits.sym);
   if(!cipher_name) {
      return std::nullopt;
   }

   const auto mode_name = cipher_mode_tss2_to_botan(cipher_def.mode.sym);
   if(!mode_name) {
      return std::nullopt;
   }

   return Botan::fmt("{}({})", mode_name.value(), cipher_name.value());
}

[[nodiscard]] inline std::optional<TPMT_SYM_DEF> cipher_botan_to_tss2(std::string_view algo_name) noexcept {
   SCAN_Name spec(algo_name);
   if(spec.arg_count() == 0) {
      return std::nullopt;
   }

   const auto cipher = block_cipher_botan_to_tss2(spec.arg(0));
   const auto mode = cipher_mode_botan_to_tss2(spec.algo_name());

   if(!cipher || !mode) {
      return std::nullopt;
   }

   return TPMT_SYM_DEF{
      .algorithm = cipher->first,
      .keyBits = {.sym = cipher->second},
      .mode = {.sym = mode.value()},
   };
}

[[nodiscard]] inline TPMT_SYM_DEF get_tpm2_sym_cipher_spec(std::string_view algo_name) {
   if(auto cipher = cipher_botan_to_tss2(algo_name)) {
      return cipher.value();
   }

   throw Lookup_Error("TPM 2.0 Symmetric Cipher Spec", algo_name);
}

[[nodiscard]] inline std::optional<TPMI_ALG_SIG_SCHEME> signature_scheme_botan_to_tss2(std::string_view name) noexcept {
   if(name == "EMSA_PKCS1" || name == "PKCS1v15" || name == "EMSA-PKCS1-v1_5" || name == "EMSA3") {
      return TPM2_ALG_RSASSA;
   } else if(name == "PSS" || name == "PSSR" || name == "EMSA-PSS" || name == "PSS-MGF1" || name == "EMSA4") {
      return TPM2_ALG_RSAPSS;
   } else {
      return std::nullopt;
   }
}

[[nodiscard]] inline std::optional<TPMI_ALG_ASYM_SCHEME> asymmetric_encryption_scheme_botan_to_tss2(
   std::string_view name) noexcept {
   if(name == "OAEP" || name == "EME-OAEP" || name == "EME1") {
      return TPM2_ALG_OAEP;
   } else if(name == "PKCS1v15" || name == "EME-PKCS1-v1_5") {
      return TPM2_ALG_RSAES;
   } else if(name == "Raw") {
      return TPM2_ALG_NULL;
   } else {
      return std::nullopt;
   }
}

}  // namespace Botan::TPM2

#endif
