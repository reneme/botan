/*
* TPM 2.0 RSA Key Wrappres
* (C) 2024 Jack Lloyd
* (C) 2024 René Meusel, Amos Treiber - Rohde & Schwarz Cybersecurity GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/tpm2_rsa.h>

#include <botan/hash.h>
#include <botan/pk_ops.h>
#include <botan/rsa.h>

#include <botan/internal/emsa.h>
#include <botan/internal/fmt.h>
#include <botan/internal/scan_name.h>
#include <botan/internal/stl_util.h>
#include <botan/internal/tpm2_algo_mappings.h>
#include <botan/internal/tpm2_hash.h>
#include <botan/internal/tpm2_util.h>

#include <tss2/tss2_esys.h>
#include <tss2/tss2_mu.h>

namespace Botan::TPM2 {

namespace {

Object make_persistent_object(const std::shared_ptr<Context>& ctx,
                              uint32_t persistent_object_handle,
                              std::span<const uint8_t> auth_value,
                              const SessionBundle& sessions) {
   BOTAN_ARG_CHECK(
      TPM2_PERSISTENT_FIRST <= persistent_object_handle && persistent_object_handle <= TPM2_PERSISTENT_LAST,
      "persistent_object_handle out of range");
   const bool is_persistent = value_exists(ctx->persistent_handles(), persistent_object_handle);
   BOTAN_STATE_CHECK(is_persistent);

   Object object(ctx);

   check_rc(
      "Esys_TR_FromTPMPublic",
      Esys_TR_FromTPMPublic(
         inner(ctx), persistent_object_handle, sessions[0], sessions[1], sessions[2], out_transient_handle(object)));

   if(!auth_value.empty()) {
      const auto user_auth = copy_into<TPM2B_AUTH>(auth_value);
      check_rc("Esys_TR_SetAuth", Esys_TR_SetAuth(inner(ctx), object.transient_handle(), &user_auth));
   }

   check_rc("Esys_TR_GetTpmHandle",
            Esys_TR_GetTpmHandle(inner(ctx), object.transient_handle(), out_persistent_handle(object)));

   return object;
}

}  // namespace

std::unique_ptr<RSA_PrivateKey> RSA_PrivateKey::create_transient(const std::shared_ptr<Context>& ctx,
                                                                 const SessionBundle& sessions,
                                                                 std::span<const uint8_t> auth_value,
                                                                 const RSA_PrivateKey& parent,
                                                                 uint16_t keylength,
                                                                 std::optional<uint32_t> exponent) {
   // TODO: Figure out how to use this properly. The Architecture Document
   //       states that the key derivation incorporates the data in both
   //       sensitive.sensitive.data and in public_template.unique.rsa.
   //
   // See Section 28.2 here:
   // https://trustedcomputinggroup.org/wp-content/uploads/TCG_TPM2_r1p59_Part1_Architecture_pub.pdf
   TPM2B_SENSITIVE_CREATE sensitive_data = {
      .size = 0,
      .sensitive =
         {
            .userAuth = copy_into<TPM2B_AUTH>(auth_value),
            .data = init_empty<TPM2B_SENSITIVE_DATA>(),
         },
   };

   TPMT_PUBLIC key_template = {
      .type = TPM2_ALG_RSA,
      .nameAlg = TPM2_ALG_SHA256,
      .objectAttributes = (TPMA_OBJECT_USERWITHAUTH | TPMA_OBJECT_RESTRICTED | TPMA_OBJECT_FIXEDTPM |
                           TPMA_OBJECT_FIXEDPARENT | TPMA_OBJECT_SENSITIVEDATAORIGIN | TPMA_OBJECT_SIGN_ENCRYPT),
      .authPolicy = init_empty<TPM2B_DIGEST>(),
      .parameters =
         {
            .rsaDetail =
               {
                  .symmetric =
                     {
                        .algorithm = TPM2_ALG_NULL,
                        .keyBits = {.aes = 0},
                        .mode = {.aes = 0},
                     },
                  .scheme =
                     {
                        .scheme = TPM2_ALG_RSAPSS,
                        .details = {.rsapss = {.hashAlg = TPM2_ALG_SHA256}},
                     },
                  .keyBits = keylength,
                  .exponent = exponent.value_or(0 /* default value - 2^16 + 1*/),
               },
         },
      // TODO: perhaps fill this somehow: see above...
      .unique = {.rsa = init_empty<TPM2B_PUBLIC_KEY_RSA>()},
   };

   return create_transient_from_template(ctx, sessions, parent, &key_template, &sensitive_data);
}

std::unique_ptr<RSA_PrivateKey> RSA_PrivateKey::create_transient_from_template(
   const std::shared_ptr<Context>& ctx,
   const SessionBundle& sessions,
   const RSA_PrivateKey& parent,
   const TPMT_PUBLIC* key_template,
   const TPM2B_SENSITIVE_CREATE* sensitive_data) {
   BOTAN_ARG_CHECK(key_template->type == TPM2_ALG_RSA, "key_template is not for an RSA key");

   const auto marshalled_template = [&] {
      TPM2B_TEMPLATE result = {};
      size_t offset = 0;
      check_rc("Tss2_MU_TPMT_PUBLIC_Marshal",
               Tss2_MU_TPMT_PUBLIC_Marshal(key_template, result.buffer, sizeof(TPMT_PUBLIC), &offset));
      result.size = offset;
      return result;
   }();

   Object handle(ctx);
   unique_esys_ptr<TPM2B_PRIVATE> private_bytes;
   unique_esys_ptr<TPM2B_PUBLIC> public_info;

   check_rc("Esys_CreateLoaded",
            Esys_CreateLoaded(inner(ctx),
                              parent.handles().transient_handle(),
                              sessions[0],
                              sessions[1],
                              sessions[2],
                              sensitive_data,
                              &marshalled_template,
                              out_transient_handle(handle),
                              out_ptr(private_bytes),
                              out_ptr(public_info)));
   BOTAN_ASSERT_NONNULL(private_bytes);
   BOTAN_ASSERT_NOMSG(public_info->publicArea.type == TPM2_ALG_RSA);
   BOTAN_ASSERT_NOMSG(handle.has_transient_handle());

   return std::unique_ptr<RSA_PrivateKey>(new RSA_PrivateKey(std::move(handle),
                                                             copy_into<std::vector<uint8_t>>(*private_bytes),
                                                             rsa_pubkey_from_tss2_public(public_info.get()),
                                                             sessions));
}

std::unique_ptr<RSA_PublicKey> RSA_PublicKey::from_persistent(const std::shared_ptr<Context>& ctx,
                                                              uint32_t persistent_object_handle,
                                                              const SessionBundle& sessions) {
   return std::unique_ptr<RSA_PublicKey>(
      new RSA_PublicKey(make_persistent_object(ctx, persistent_object_handle, {}, sessions), sessions));
}

RSA_PublicKey::RSA_PublicKey(Object object, SessionBundle sessions) :
      Botan::RSA_PublicKey(rsa_pubkey_from_tss2_public(object._public_info(sessions, TPM2_ALG_RSA).pub.get())),
      m_handle(std::move(object)),
      m_sessions(std::move(sessions)) {}

std::unique_ptr<RSA_PrivateKey> RSA_PrivateKey::from_persistent(const std::shared_ptr<Context>& ctx,
                                                                uint32_t persistent_object_handle,
                                                                std::span<const uint8_t> auth_value,
                                                                const SessionBundle& sessions) {
   return std::unique_ptr<RSA_PrivateKey>(
      new RSA_PrivateKey(make_persistent_object(ctx, persistent_object_handle, auth_value, sessions), sessions));
}

RSA_PrivateKey::RSA_PrivateKey(Object handle, SessionBundle sessions) :
      RSA_PrivateKey(handle.context(),
                     {},
                     rsa_pubkey_from_tss2_public(handle._public_info(sessions, TPM2_ALG_RSA).pub.get()),
                     std::move(sessions)) {
   // Moving the handle into the member down here, to be able to access it
   // safely in the initializer list for rsa_pubkey_from_tss2_public().
   m_handle = std::move(handle);
}

namespace {

struct AlgorithmSelection {
      TPMT_SIG_SCHEME signature_scheme;
      std::string hash_name;
};

AlgorithmSelection select_algorithms(std::string_view padding) {
   const SCAN_Name req(padding);
   if(req.arg_count() == 0) {
      throw Invalid_Argument("RSA signing padding scheme must at least specify a hash function");
   }

   const auto scheme = signature_scheme_botan_to_tss2(req.algo_name());
   if(!scheme) {
      throw Not_Implemented("RSA signing with padding scheme " + req.algo_name());
   }

   if(scheme.value() == TPM2_ALG_RSAPSS && req.arg_count() != 1) {
      throw Not_Implemented("RSA signing using PSS with MGF1");
   }

   return {TPMT_SIG_SCHEME{
              .scheme = scheme.value(),
              .details = {.any = {.hashAlg = get_tpm2_hash_type(req.arg(0))}},
           },
           req.arg(0)};
}

/**
 * Signing with a restricted key requires a validation ticket that is provided
 * when hashing the data to sign on the TPM. Otherwise, it is fine to hash the
 * data in software.
 *
 * @param key_handle  the key to create the signature with
 * @param sessions    the sessions to use for the TPM operations
 * @param hash_name   the name of the hash function to use
 *
 * @return a HashFunction that hashes in hardware if the key is restricted
 */
std::unique_ptr<Botan::HashFunction> create_hash_function(const Object& key_handle,
                                                          const SessionBundle& sessions,
                                                          std::string_view hash_name) {
   const bool is_restricted =
      key_handle._public_info(sessions, TPM2_ALG_RSA).pub->publicArea.objectAttributes & TPMA_OBJECT_RESTRICTED;

   if(is_restricted) {
      // TODO: this could also be ENDORSEMENT or PLATFORM, and we're not 100% sure
      //       that OWNER is always the right choice here.
      const TPMI_RH_HIERARCHY hierarchy = ESYS_TR_RH_OWNER;
      return std::make_unique<HashFunction>(key_handle.context(), hash_name, hierarchy, sessions);
   } else {
      return Botan::HashFunction::create_or_throw(hash_name);
   }
}

/**
 * If the key is restricted, this will transparently use the TPM to hash the
 * data to obtain a validation ticket.
 *
 * TPM Library, Part 1: Architecture", Section 11.4.6.3 (4)
 *    This ticket is used to indicate that a digest of external data is safe to
 *    sign using a restricted signing key. A restricted signing key may only
 *    sign a digest that was produced by the TPM. [...] This prevents forgeries
 *    of attestation data.
 */
class RSA_Signature_Operation : public PK_Ops::Signature {
   private:
      RSA_Signature_Operation(const Object& object,
                              const SessionBundle& sessions,
                              const AlgorithmSelection& algorithms) :
            m_key_handle(object),
            m_sessions(sessions),
            m_scheme(algorithms.signature_scheme),
            m_hash(create_hash_function(m_key_handle, m_sessions, algorithms.hash_name)) {
         BOTAN_ASSERT_NONNULL(m_hash);
      }

   public:
      RSA_Signature_Operation(const Object& object, const SessionBundle& sessions, std::string_view padding) :
            RSA_Signature_Operation(object, sessions, select_algorithms(padding)) {}

      void update(std::span<const uint8_t> msg) override { m_hash->update(msg); }

      std::vector<uint8_t> sign(RandomNumberGenerator& /* rng */) override {
         if(auto hash = dynamic_cast<HashFunction*>(m_hash.get())) {
            // This is a TPM2-based hash object that calculated the digest on
            // the TPM. We can use the validation ticket to create the signature.
            auto [digest, validation] = hash->final_with_ticket();
            return create_signature(digest.get(), validation.get());
         } else {
            // This is a software hash, so we have to stub the validation ticket
            // and create the signature without it.
            TPMT_TK_HASHCHECK dummy_validation = {
               .tag = TPM2_ST_HASHCHECK,
               .hierarchy = TPM2_RH_NULL,
               .digest = init_empty<TPM2B_DIGEST>(),
            };

            auto digest = init_with_size<TPM2B_DIGEST>(m_hash->output_length());
            m_hash->final(as_span(digest));
            return create_signature(&digest, &dummy_validation);
         }
      }

      size_t signature_length() const override {
         return m_key_handle._public_info(m_sessions, TPM2_ALG_RSA).pub->publicArea.parameters.rsaDetail.keyBits / 8;
      }

      std::string hash_function() const override { return m_hash->name(); }

   private:
      std::vector<uint8_t> create_signature(const TPM2B_DIGEST* digest, const TPMT_TK_HASHCHECK* validation) {
         unique_esys_ptr<TPMT_SIGNATURE> signature;
         check_rc("Esys_Sign",
                  Esys_Sign(inner(m_key_handle.context()),
                            m_key_handle.transient_handle(),
                            m_sessions[0],
                            m_sessions[1],
                            m_sessions[2],
                            digest,
                            &m_scheme,
                            validation,
                            out_ptr(signature)));

         BOTAN_ASSERT_NONNULL(signature);
         const auto& sig = [&]() -> TPMS_SIGNATURE_RSA& {
            if(signature->sigAlg == TPM2_ALG_RSASSA) {
               return signature->signature.rsassa;
            } else if(signature->sigAlg == TPM2_ALG_RSAPSS) {
               return signature->signature.rsapss;
            }

            throw Invalid_State(fmt("TPM2 returned an unexpected signature scheme {}", signature->sigAlg));
         }();

         BOTAN_ASSERT_NOMSG(sig.hash == m_scheme.details.any.hashAlg);

         return copy_into<std::vector<uint8_t>>(sig.sig);
      };

   private:
      const Object& m_key_handle;
      const SessionBundle& m_sessions;
      TPMT_SIG_SCHEME m_scheme;
      std::unique_ptr<Botan::HashFunction> m_hash;
};

/**
 * Signature verification on the TPM. This does not require a validation ticket,
 * therefore the hash is always calculated in software.
 */
class RSA_Verification_Operation : public PK_Ops::Verification {
   private:
      RSA_Verification_Operation(const Object& object,
                                 const SessionBundle& sessions,
                                 const AlgorithmSelection& algorithms) :
            m_key_handle(object),
            m_sessions(sessions),
            m_scheme(algorithms.signature_scheme),
            m_hash(Botan::HashFunction::create_or_throw(algorithms.hash_name)) {}

   public:
      RSA_Verification_Operation(const Object& object, const SessionBundle& sessions, std::string_view padding) :
            RSA_Verification_Operation(object, sessions, select_algorithms(padding)) {}

      void update(std::span<const uint8_t> msg) override { m_hash->update(msg); }

      bool is_valid_signature(std::span<const uint8_t> sig_data) override {
         auto digest = init_with_size<TPM2B_DIGEST>(m_hash->output_length());
         m_hash->final(as_span(digest));

         const auto signature = [&]() -> TPMT_SIGNATURE {
            TPMT_SIGNATURE sig;
            sig.sigAlg = m_scheme.scheme;
            sig.signature.any.hashAlg = m_scheme.details.any.hashAlg;

            if(sig.sigAlg == TPM2_ALG_RSASSA) {
               copy_into(sig.signature.rsassa.sig, sig_data);
            } else if(sig.sigAlg == TPM2_ALG_RSAPSS) {
               copy_into(sig.signature.rsapss.sig, sig_data);
            } else {
               throw Invalid_State(fmt("Requested an unexpected signature scheme {}", sig.sigAlg));
            }

            return sig;
         }();

         // If the signature is not valid, this returns TPM2_RC_SIGNATURE.
         const auto rc = check_rc_expecting<TPM2_RC_SIGNATURE>("Esys_VerifySignature",
                                                               Esys_VerifySignature(inner(m_key_handle.context()),
                                                                                    m_key_handle.transient_handle(),
                                                                                    m_sessions[0],
                                                                                    m_sessions[1],
                                                                                    m_sessions[2],
                                                                                    &digest,
                                                                                    &signature,
                                                                                    nullptr /* validation */));

         return rc == TPM2_RC_SUCCESS;
      }

      std::string hash_function() const override { return m_hash->name(); }

   private:
      const Object& m_key_handle;
      const SessionBundle& m_sessions;
      TPMT_SIG_SCHEME m_scheme;
      std::unique_ptr<Botan::HashFunction> m_hash;
};

}  // namespace

secure_vector<uint8_t> RSA_PrivateKey::private_key_bits() const {
   if(m_handle.has_persistent_handle()) {
      throw Not_Implemented("cannot export private key bits from a TPM2 key");
   } else {
      BOTAN_ASSERT_NOMSG(!m_private_blob.empty());
      return Botan::lock(m_private_blob);
   }
}

std::unique_ptr<PK_Ops::Verification> RSA_PublicKey::create_verification_op(std::string_view params,
                                                                            std::string_view provider) const {
   BOTAN_UNUSED(provider);
   return std::make_unique<RSA_Verification_Operation>(m_handle, m_sessions, params);
}

std::unique_ptr<PK_Ops::Signature> RSA_PrivateKey::create_signature_op(RandomNumberGenerator& rng,
                                                                       std::string_view params,
                                                                       std::string_view provider) const {
   BOTAN_UNUSED(rng);
   BOTAN_UNUSED(provider);
   return std::make_unique<RSA_Signature_Operation>(m_handle, m_sessions, params);
}

}  // namespace Botan::TPM2
