/*
* TPM 2.0 RSA Key Wrappres
* (C) 2024 Jack Lloyd
* (C) 2024 René Meusel, Amos Treiber - Rohde & Schwarz Cybersecurity GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/tpm2_rsa.h>

#include <botan/der_enc.h>
#include <botan/hash.h>
#include <botan/pk_ops.h>
#include <botan/rsa.h>

#include <botan/internal/emsa.h>
#include <botan/internal/fmt.h>
#include <botan/internal/scan_name.h>
#include <botan/internal/stl_util.h>
#include <botan/internal/tpm2_hash.h>
#include <botan/internal/tpm2_util.h>
#include <botan/internal/workfactor.h>

#include <tss2/tss2_esys.h>

namespace Botan::TPM2 {

namespace {

std::pair<TPMT_SIG_SCHEME, HashFunction> select_scheme(const std::shared_ptr<Context>& ctx, std::string_view padding) {
   SCAN_Name req(padding);

   const auto scheme = [&]() -> TPMI_ALG_SIG_SCHEME {
      if(req.algo_name() == "EMSA_PKCS1" || req.algo_name() == "PKCS1v15" || req.algo_name() == "EMSA-PKCS1-v1_5" ||
         req.algo_name() == "EMSA3") {
         return TPM2_ALG_RSASSA;
      }

      if(req.algo_name() == "PSS" || req.algo_name() == "PSSR" || req.algo_name() == "EMSA-PSS" ||
         req.algo_name() == "PSS-MGF1" || req.algo_name() == "EMSA4") {
         if(req.arg_count() != 1) {
            throw Not_Implemented("RSA signing using PSS with MGF1");
         }
         return TPM2_ALG_RSAPSS;
      }

      throw Not_Implemented("RSA signing with padding scheme " + req.algo_name());
   }();

   if(req.arg_count() == 0) {
      throw Invalid_Argument("RSA signing padding scheme must at least specify a hash function");
   }

   auto hash = HashFunction(ctx, req.arg(0));
   const auto hash_type = hash.type();

   return {TPMT_SIG_SCHEME{
              .scheme = scheme,
              .details = {.any = {.hashAlg = hash_type}},
           },
           std::move(hash)};
}

BigInt n(const PublicInfo& pi) {
   BOTAN_ASSERT_NONNULL(pi.pub);
   return BigInt(as_span(pi.pub->publicArea.unique.rsa));
}

BigInt e(const PublicInfo& pi) {
   BOTAN_ASSERT_NONNULL(pi.pub);
   // TPM2 may report 0 when the exponent is 'the default' (2^16 + 1)
   const auto exponent = pi.pub->publicArea.parameters.rsaDetail.exponent;
   return (exponent == 0) ? 65537 : exponent;
}

Object make_persistent_object(const std::shared_ptr<Context>& ctx,
                              uint32_t persistent_object_handle,
                              std::span<const uint8_t> auth_value) {
   BOTAN_ARG_CHECK(
      TPM2_PERSISTENT_FIRST <= persistent_object_handle && persistent_object_handle <= TPM2_PERSISTENT_LAST,
      "persistent_object_handle out of range");
   const bool is_persistent = ctx->in_persistent_handles(persistent_object_handle);
   BOTAN_STATE_CHECK(is_persistent);

   Object object(ctx);

   check_tss2_rc("Esys_TR_FromTPMPublic",
                 Esys_TR_FromTPMPublic(inner(ctx),
                                       persistent_object_handle,
                                       ctx->session_handle(0),
                                       ctx->session_handle(1),
                                       ctx->session_handle(2),
                                       out_transient_handle(object)));

   const auto user_auth = copy_into<TPM2B_AUTH>(auth_value);
   check_tss2_rc("Esys_TR_SetAuth", Esys_TR_SetAuth(inner(ctx), object.transient_handle(), &user_auth));

   check_tss2_rc("Esys_TR_GetTpmHandle",
                 Esys_TR_GetTpmHandle(inner(ctx), object.transient_handle(), out_persistent_handle(object)));

   return object;
}

}  // namespace

RSA_PublicKey RSA_PublicKey::from_persistent(const std::shared_ptr<Context>& ctx,
                                             uint32_t persistent_object_handle,
                                             std::span<const uint8_t> auth_value) {
   return make_persistent_object(ctx, persistent_object_handle, auth_value);
}

RSA_PublicKey::RSA_PublicKey(Object object) :
      Botan::RSA_PublicKey(n(object._public_info(TPM2_ALG_RSA)), e(object._public_info(TPM2_ALG_RSA))),
      m_handle(std::move(object)) {}

RSA_PrivateKey RSA_PrivateKey::from_persistent(const std::shared_ptr<Context>& ctx,
                                               uint32_t persistent_object_handle,
                                               std::span<const uint8_t> auth_value) {
   return make_persistent_object(ctx, persistent_object_handle, auth_value);
}

RSA_PrivateKey::RSA_PrivateKey(Object object) :
      Botan::RSA_PublicKey(n(object._public_info(TPM2_ALG_RSA)), e(object._public_info(TPM2_ALG_RSA))),
      m_handle(std::move(object)) {}

std::unique_ptr<Public_Key> RSA_PrivateKey::public_key() const {
   return std::make_unique<Botan::RSA_PublicKey>(algorithm_identifier(), public_key_bits());
}

namespace {

class RSA_Signature_Operation : public PK_Ops::Signature {
   private:
      RSA_Signature_Operation(const Object& object, std::pair<TPMT_SIG_SCHEME, HashFunction> scheme) :
            m_key_handle(object), m_scheme(scheme.first), m_hash(std::move(scheme.second)) {}

   public:
      RSA_Signature_Operation(const Object& object, std::string_view padding) :
            RSA_Signature_Operation(object, select_scheme(object.context(), padding)){};

      void update(std::span<const uint8_t> msg) override { m_hash.update(msg); }

      std::vector<uint8_t> sign(RandomNumberGenerator& /* rng */) override {
         auto [digest, validation] = m_hash.final_with_ticket();

         unique_esys_ptr<TPMT_SIGNATURE> signature;
         check_tss2_rc("Esys_Sign",
                       Esys_Sign(inner(m_key_handle.context()),
                                 m_key_handle.transient_handle(),
                                 m_key_handle.context()->session_handle(0),
                                 m_key_handle.context()->session_handle(1),
                                 m_key_handle.context()->session_handle(2),
                                 digest.get(),
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

         BOTAN_ASSERT_NOMSG(sig.hash == m_hash.type());

         return copy_into<std::vector<uint8_t>>(sig.sig);
      }

      size_t signature_length() const override {
         return m_key_handle._public_info(TPM2_ALG_RSA).pub->publicArea.parameters.rsaDetail.keyBits / 8;
      }

      std::string hash_function() const override { return m_hash.name(); }

   private:
      const Object& m_key_handle;
      TPMT_SIG_SCHEME m_scheme;
      HashFunction m_hash;
};

class RSA_Verification_Operation : public PK_Ops::Verification {
   private:
      RSA_Verification_Operation(const Object& object, std::pair<TPMT_SIG_SCHEME, HashFunction> scheme) :
            m_key_handle(object), m_scheme(scheme.first), m_hash(std::move(scheme.second)) {}

   public:
      RSA_Verification_Operation(const Object& object, std::string_view padding) :
            RSA_Verification_Operation(object, select_scheme(object.context(), padding)){};

      void update(std::span<const uint8_t> msg) override { m_hash.update(msg); }

      bool is_valid_signature(std::span<const uint8_t> sig_data) override {
         auto [digest, validation] = m_hash.final_with_ticket();

         const auto signature = [&]() -> TPMT_SIGNATURE {
            TPMT_SIGNATURE signature;
            signature.sigAlg = m_scheme.scheme;
            signature.signature.any.hashAlg = m_hash.type();

            if(signature.sigAlg == TPM2_ALG_RSASSA) {
               copy_into(signature.signature.rsassa.sig, sig_data);
            } else if(signature.sigAlg == TPM2_ALG_RSAPSS) {
               copy_into(signature.signature.rsapss.sig, sig_data);
            } else {
               throw Invalid_State(fmt("Requested an unexpected signature scheme {}", signature.sigAlg));
            }

            return signature;
         }();

         unique_esys_ptr<TPMT_TK_VERIFIED> result;
         const auto rc = Esys_VerifySignature(inner(m_key_handle.context()),
                                              m_key_handle.transient_handle(),
                                              m_key_handle.context()->session_handle(0),
                                              m_key_handle.context()->session_handle(1),
                                              m_key_handle.context()->session_handle(2),
                                              digest.get(),
                                              &signature,
                                              out_ptr(result));

         TSS2_RC_INFO info;
         check_tss2_rc("Tss2_RC_DecodeInfo", Tss2_RC_DecodeInfo(rc, &info));

         if(info.error == TPM2_RC_SIGNATURE) {
            return false;
         }

         check_tss2_rc("Esys_VerifySignature", rc);

         return true;
      }

      std::string hash_function() const override { return m_hash.name(); }

   private:
      const Object& m_key_handle;
      TPMT_SIG_SCHEME m_scheme;
      HashFunction m_hash;
};

}  // namespace

std::unique_ptr<PK_Ops::Verification> RSA_PublicKey::create_verification_op(std::string_view params,
                                                                            std::string_view provider) const {
   BOTAN_UNUSED(provider);
   return std::make_unique<RSA_Verification_Operation>(m_handle, params);
}

std::unique_ptr<PK_Ops::Signature> RSA_PrivateKey::create_signature_op(RandomNumberGenerator& rng,
                                                                       std::string_view params,
                                                                       std::string_view provider) const {
   BOTAN_UNUSED(rng);
   BOTAN_UNUSED(provider);
   return std::make_unique<RSA_Signature_Operation>(m_handle, params);
}

}  // namespace Botan::TPM2
