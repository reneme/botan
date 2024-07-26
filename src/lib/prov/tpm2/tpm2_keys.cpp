/*
* TPM 2 Keys
* (C) 2024 Jack Lloyd
* (C) 2024 René Meusel, Amos Treiber - Rohde & Schwarz Cybersecurity GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/tpm2_keys.h>

#include <botan/der_enc.h>
#include <botan/hash.h>
#include <botan/pk_ops.h>
#include <botan/rsa.h>
#include <botan/internal/ct_utils.h>  // TODO: remove me
#include <botan/internal/emsa.h>
#include <botan/internal/fmt.h>
#include <botan/internal/scan_name.h>
#include <botan/internal/stl_util.h>
#include <botan/internal/tpm2_util.h>
#include <botan/internal/workfactor.h>

#include <iostream>
#include <tss2/tss2_esys.h>

namespace {
// Signing key template. TODO: Proper Key Templates
const TPM2B_PUBLIC rsa_sign_template = {
   .size = 0,
   .publicArea = {
      .type = TPM2_ALG_RSA,
      .nameAlg = TPM2_ALG_SHA256,
      .objectAttributes = (TPMA_OBJECT_SIGN_ENCRYPT | TPMA_OBJECT_USERWITHAUTH | TPMA_OBJECT_FIXEDTPM |
                           TPMA_OBJECT_FIXEDPARENT | TPMA_OBJECT_SENSITIVEDATAORIGIN),
      .authPolicy = {0},  // No policy beyond HMAC sessions here
      .parameters = {.rsaDetail = {.symmetric = {.algorithm = TPM2_ALG_NULL, .keyBits = {.aes = 0}, .mode = {.aes = 0}},
                                   .scheme = {.scheme = TPM2_ALG_RSAPSS,
                                              .details = {.rsassa = {.hashAlg = TPM2_ALG_SHA256}}},
                                   .keyBits = 2048,
                                   .exponent = 0}},
      .unique = {.rsa = {.size = 0, .buffer = {0}}}}};

TPM2B_SENSITIVE_CREATE in_sensitive_from_auth_val(const std::string& auth_val_view) {
   BOTAN_ASSERT_NOMSG(auth_val_view.size() <= std::numeric_limits<uint16_t>::max());
   TPM2B_AUTH auth_val = {.size = static_cast<uint16_t>(auth_val_view.size()), .buffer = {0}};
   std::copy(auth_val_view.begin(), auth_val_view.end(), auth_val.buffer);  // TODO: Is this the best way?

   return {.size = 0, .sensitive = {.userAuth = auth_val, .data = {.size = 0, .buffer = {0}}}};
}

}  // namespace

namespace Botan {

TPM2_Key::TPM2_Key(std::shared_ptr<TPM2_Context> ctx, size_t key_persistent_id, const std::string& auth_val) :
      m_ctx(std::move(ctx)) {
   TPMI_DH_PERSISTENT persistent_handle = TPM2_PERSISTENT_FIRST + key_persistent_id;
   BOTAN_ASSERT_NOMSG(persistent_handle <= TPM2_PERSISTENT_LAST);

   m_is_loaded = m_ctx->in_persistent_handles(persistent_handle);

   if(!m_is_loaded) {
      create_new(persistent_handle, auth_val);
   } else {
      load_existing(persistent_handle, auth_val);
   }
}

void TPM2_Key::create_new(uint32_t /* key_handle */, const std::string& /* auth_val */) {
   throw Not_Implemented("key management is NYI");  //TODO: Implement

   // unique_esys_ptr<TPM2B_PRIVATE> out_private;
   // unique_esys_ptr<TPM2B_PUBLIC> out_public;
   // unique_esys_ptr<TPM2B_CREATION_DATA> creation_data;
   // unique_esys_ptr<TPM2B_DIGEST> creation_hash;
   // unique_esys_ptr<TPMT_TK_CREATION> creation_ticket;

   // TPM2B_DATA outside_info = {.size = 0, .buffer = {0}};
   // TPML_PCR_SELECTION creation_pcr = {.count = 0};

   // const auto in_sensitive = in_sensitive_from_auth_val(auth_val);

   // // Create the signing key
   // check_tss2_rc("Esys_Create",
   //               Esys_Create(inner(m_ctx),
   //                           m_parent_handle,
   //                           m_ctx->session_handle(0),
   //                           m_ctx->session_handle(1),
   //                           m_ctx->session_handle(2),
   //                           &in_sensitive,
   //                           &rsa_sign_template,
   //                           &outside_info,
   //                           &creation_pcr,
   //                           out_ptr(out_private),
   //                           out_ptr(out_public),
   //                           out_ptr(creation_data),
   //                           out_ptr(creation_hash),
   //                           out_ptr(creation_ticket)));

   // m_public_key_bits = std::vector(out_public->publicArea.unique.rsa.buffer,
   //                                 out_public->publicArea.unique.rsa.buffer + out_public->publicArea.unique.rsa.size);

   // // Load the signing key
   // check_tss2_rc("Esys_Load",
   //               Esys_Load(inner(m_ctx),
   //                         m_ctx->spk_handle(),
   //                         m_ctx->session_handle(0),
   //                         m_ctx->session_handle(1),
   //                         m_ctx->session_handle(2),
   //                         out_private.get(),
   //                         out_public.get(),
   //                         &m_transient_key_handle));

   // // Authenticate it via authVal
   // check_tss2_rc("Esys_TR_SetAuth",
   //               Esys_TR_SetAuth(inner(m_ctx), m_transient_key_handle, &in_sensitive.sensitive.userAuth));

   // // Make the key persistent
   // ESYS_TR persistent_handle_out = ESYS_TR_NONE;  // Does not need to be flushed

   // check_tss2_rc("Esys_EvictControl",
   //               Esys_EvictControl(inner(m_ctx),
   //                                 ESYS_TR_RH_OWNER,
   //                                 m_transient_key_handle,
   //                                 m_ctx->session_handle(0),
   //                                 m_ctx->session_handle(1),
   //                                 m_ctx->session_handle(2),
   //                                 key_handle,
   //                                 &persistent_handle_out));

   // check_tss2_rc("Esys_TR_GetTpmHandle",
   //               Esys_TR_GetTpmHandle(inner(m_ctx), persistent_handle_out, &m_persistent_key_handle));
}

void TPM2_Key::load_existing(uint32_t key_handle, const std::string& auth_val) {
   // Load the key
   check_tss2_rc("Esys_TR_FromTPMPublic",
                 Esys_TR_FromTPMPublic(inner(m_ctx),
                                       key_handle,
                                       m_ctx->session_handle(0),
                                       m_ctx->session_handle(1),
                                       m_ctx->session_handle(2),
                                       &m_transient_key_handle));

   // Authenticate it via auth_val
   const auto in_sensitive = in_sensitive_from_auth_val(auth_val);
   check_tss2_rc("Esys_TR_SetAuth",
                 Esys_TR_SetAuth(inner(m_ctx), m_transient_key_handle, &in_sensitive.sensitive.userAuth));

   check_tss2_rc("Esys_TR_GetTpmHandle",
                 Esys_TR_GetTpmHandle(inner(m_ctx), m_transient_key_handle, &m_persistent_key_handle));
}

TPM2_Key::~TPM2_Key() {
   if(!m_is_loaded) {
      // No need to flush after TR_FromTPMPublic
      check_tss2_rc("Esys_FlushContext", Esys_FlushContext(inner(m_ctx), m_transient_key_handle));
   }
   // No need to flush persistent handles
}

namespace {

struct PublicInfo {
      unique_esys_ptr<TPM2B_PUBLIC> pub;
      unique_esys_ptr<TPM2B_NAME> name;
      unique_esys_ptr<TPM2B_NAME> qualified_name;
};

template <TPMI_ALG_PUBLIC expected_type>
PublicInfo read_public_info(const std::shared_ptr<TPM2_Context>& ctx, ESYS_TR handle) {
   PublicInfo result;

   check_tss2_rc("Esys_ReadPublic",
                 Esys_ReadPublic(inner(ctx),
                                 handle,
                                 ctx->session_handle(0),
                                 ctx->session_handle(1),
                                 ctx->session_handle(2),
                                 out_ptr(result.pub),
                                 out_ptr(result.name),
                                 out_ptr(result.qualified_name)));
   BOTAN_STATE_CHECK(result.pub->publicArea.type == expected_type);
   BOTAN_ASSERT_NONNULL(result.pub);

   return result;
}

template <typename T>
std::span<const uint8_t> from_tpm2_buffer(const T& tpm_buffer) {
   return std::span{tpm_buffer.buffer, tpm_buffer.size};
}

}  // namespace

std::unique_ptr<Public_Key> TPM2_Key::public_key() const {
   // TODO: Probably this should return an TPM2_RSA_PublicKey at one point
   return std::make_unique<RSA_PublicKey>(algorithm_identifier(), public_key_bits());
}

size_t TPM2_Key::estimated_strength() const {
   return if_work_factor(key_length());
}

size_t TPM2_Key::key_length() const {
   return read_public_info<TPM2_ALG_RSA>(m_ctx, m_transient_key_handle).pub->publicArea.parameters.rsaDetail.keyBits;
}

AlgorithmIdentifier TPM2_Key::algorithm_identifier() const {
   return AlgorithmIdentifier(object_identifier(), AlgorithmIdentifier::USE_NULL_PARAM);
}

std::vector<uint8_t> TPM2_Key::public_key_bits() const {
   auto public_info = read_public_info<TPM2_ALG_RSA>(m_ctx, m_transient_key_handle);

   const BigInt n = BigInt(from_tpm2_buffer(public_info.pub->publicArea.unique.rsa));
   const BigInt e = [&]() -> BigInt {
      const auto exponent = public_info.pub->publicArea.parameters.rsaDetail.exponent;
      // TPM2 may report 0 when the exponent is 'the default' (2^16 + 1)
      return (exponent == 0) ? 65537 : exponent;
   }();

   std::vector<uint8_t> output;
   DER_Encoder(output).start_sequence().encode(n).encode(e).end_cons();
   return output;
}

std::vector<uint8_t> TPM2_Key::raw_public_key_bits() const {
   throw Not_Implemented("An RSA public key does not provide a raw binary representation.");
}

secure_vector<uint8_t> TPM2_Key::private_key_bits() const {
   throw Not_Implemented("TPM2_Key::private_key_bits");
}

bool TPM2_Key::check_key(RandomNumberGenerator&, bool) const {
   return true;  // does not make sense on a TPM key
}

namespace {

TPMI_ALG_HASH get_tpm2_hash_type(const std::unique_ptr<HashFunction>& hash) {
   if(!hash) {
      return TPM2_ALG_NULL;
   }

   const std::string hash_name = hash->name();
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
   }

   throw Not_Implemented("TPM2 signing with hash " + hash_name);
}

std::pair<TPMT_SIG_SCHEME, std::unique_ptr<Botan::HashFunction>> prepare_padding_mechanism(std::string_view padding) {
   SCAN_Name req(padding);  // "PSS(SHA-256)"
   auto hash = [&]() -> std::unique_ptr<HashFunction> {
      if(req.arg_count() > 0) {
         return HashFunction::create(req.arg(0));
      } else {
         return nullptr;
      }
   }();

   const auto scheme = [&]() -> TPMI_ALG_SIG_SCHEME {
      if(req.algo_name() == "EMSA_PKCS1" || req.algo_name() == "PKCS1v15" || req.algo_name() == "EMSA-PKCS1-v1_5" ||
         req.algo_name() == "EMSA3") {
         if(!hash) {
            throw Not_Implemented("RSA signing using PKCS 1.5 without hash function");
         }

         return TPM2_ALG_RSASSA;
      }

      if(req.algo_name() == "PSS" || req.algo_name() == "PSSR" || req.algo_name() == "EMSA-PSS" ||
         req.algo_name() == "PSS-MGF1" || req.algo_name() == "EMSA4") {
         if(!hash) {
            throw Not_Implemented("RSA signing using PSS without hash function");
         }

         if(req.arg_count() != 1) {
            throw Not_Implemented("RSA signing using PSS with MGF1");
         }

         return TPM2_ALG_RSAPSS;
      }

      throw Not_Implemented("RSA signing with padding scheme " + req.algo_name());
   }();

   return {TPMT_SIG_SCHEME{
              .scheme = scheme,
              .details = {.any = {.hashAlg = get_tpm2_hash_type(hash)}},
           },
           std::move(hash)};
}

TPM2B_DIGEST make_tpm2b_digest(HashFunction& hash) {
   TPM2B_DIGEST dgst;
   const auto digest_size = hash.output_length();
   BOTAN_ASSERT_NOMSG(digest_size <= std::numeric_limits<decltype(dgst.size)>::max());
   dgst.size = static_cast<uint16_t>(digest_size);
   hash.final(std::span{dgst.buffer, sizeof(dgst.buffer)});
   return dgst;
}

template <concepts::resizable_byte_buffer T, typename TPM2B>
T copy_tpm2b_data(const TPM2B& data) {
   BOTAN_ASSERT_NOMSG(sizeof(data.buffer) >= data.size);
   T result;
   result.assign(data.buffer, data.buffer + data.size);
   return result;
}

class TPM2_Signature_Operation : public PK_Ops::Signature {
   public:
      TPM2_Signature_Operation(const TPM2_Key& key, std::string_view padding) : m_key(key) {
         std::tie(m_scheme, m_hash) = prepare_padding_mechanism(padding);
         BOTAN_ASSERT_NONNULL(m_hash);
      }

      void update(std::span<const uint8_t> msg) override {
         m_msg = concat(m_msg, msg);
         m_hash->update(msg);
      }

      std::vector<uint8_t> sign(RandomNumberGenerator& /* rng */) override {
         const auto digest = make_tpm2b_digest(*m_hash);

         unique_esys_ptr<TPMT_TK_HASHCHECK> validation;
         unique_esys_ptr<TPM2B_DIGEST> tpm_digest;

         TPM2B_MAX_BUFFER data;
         BOTAN_ASSERT_NOMSG(m_msg.size() <= sizeof(data.buffer));
         data.size = static_cast<uint16_t>(m_msg.size());
         copy_mem(std::span{data.buffer, data.size}, m_msg);

         check_tss2_rc(
            "Esys_Hash",
            Esys_Hash(
               inner(m_key._context()),
               m_key._context()->session_handle(0),
               m_key._context()->session_handle(1),
               m_key._context()->session_handle(2),
               &data,
               m_scheme.details.any.hashAlg,
               ESYS_TR_RH_NULL,  // TODO: options: TPM2_RH_OWNER, TPM2_RH_ENDORSEMENT, TPM2_RH_PLATFORM, TPM2_RH_NULL
               out_ptr(tpm_digest),
               out_ptr(validation)));

         // TODO: Remove, just for debugging
         BOTAN_ASSERT_NOMSG(CT::is_equal(digest.buffer, tpm_digest->buffer, tpm_digest->size).as_bool());

         unique_esys_ptr<TPMT_SIGNATURE> signature;
         check_tss2_rc("Esys_Sign",
                       Esys_Sign(inner(m_key._context()),
                                 m_key.transient_handle(),
                                 m_key._context()->session_handle(0),
                                 m_key._context()->session_handle(1),
                                 m_key._context()->session_handle(2),
                                 tpm_digest.get(),
                                 &m_scheme,
                                 validation.get(),
                                 out_ptr(signature)));

         BOTAN_ASSERT_NONNULL(signature);
         const auto& sig = [&]() -> TPMS_SIGNATURE_RSA {
            if(signature->sigAlg == TPM2_ALG_RSASSA) {
               return signature->signature.rsassa;
            } else if(signature->sigAlg == TPM2_ALG_RSAPSS) {
               return signature->signature.rsapss;
            }

            throw Invalid_State(fmt("TPM2 returned an unexpected signature scheme {}", signature->sigAlg));
         }();

         BOTAN_ASSERT_NOMSG(sig.hash == m_scheme.details.any.hashAlg);

         return copy_tpm2b_data<std::vector<uint8_t>>(sig.sig);
      }

      size_t signature_length() const override { return 512; /* TODO */ }

      std::string hash_function() const override { return m_hash->name(); }

   private:
      const TPM2_Key& m_key;
      TPMT_SIG_SCHEME m_scheme;
      std::vector<uint8_t> m_msg;
      std::unique_ptr<HashFunction> m_hash;
};

}  // namespace

std::unique_ptr<PK_Ops::Signature> TPM2_Key::create_signature_op(RandomNumberGenerator& rng,
                                                                 std::string_view params,
                                                                 std::string_view provider) const {
   BOTAN_UNUSED(rng);
   BOTAN_UNUSED(provider);
   return std::make_unique<TPM2_Signature_Operation>(*this, params);
}

}  // namespace Botan
