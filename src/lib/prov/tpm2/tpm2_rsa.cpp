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
#include <botan/internal/tpm2_algo_mappings.h>
#include <botan/internal/tpm2_hash.h>
#include <botan/internal/tpm2_util.h>
#include <botan/internal/workfactor.h>

#include <tss2/tss2_esys.h>
#include <tss2/tss2_mu.h>

namespace Botan::TPM2 {

namespace {

/// @returns a pair of the padding scheme and the hash function names
std::pair<std::string, std::string> schemes_from_padding(std::string_view padding) {
   const SCAN_Name req(padding);
   if(req.arg_count() == 0) {
      throw Invalid_Argument("RSA signing padding scheme must at least specify a hash function");
   }
   return {req.algo_name() /*Padding Scheme*/, req.arg(0) /*Hash Scheme*/};
}

class HashFunctionWrapper {
      // This class wraps a TPM2 HashFunction or a software Botan::HashFunction,
      // and returns the final hash and validation ticket. In case of a software
      // hash, the validation ticket will be null.

   public:
      static HashFunctionWrapper create_with_hashing_in_tpm(std::shared_ptr<Context> ctx,
                                                            std::string_view algorithm,
                                                            TPMI_RH_HIERARCHY hierarchy,
                                                            SessionBundle sessions) {
         return HashFunctionWrapper(
            std::make_unique<HashFunction>(std::move(ctx), algorithm, hierarchy, std::move(sessions)));
      }

      static HashFunctionWrapper create_with_hashing_in_software(std::string_view algorithm) {
         return HashFunctionWrapper(Botan::HashFunction::create_or_throw(algorithm));
      }

   public:
      void update(std::span<const uint8_t> msg) { m_hash->update(msg); }

      std::pair<unique_esys_ptr<TPM2B_DIGEST>, unique_esys_ptr<TPMT_TK_HASHCHECK>> final_with_ticket() {
         if(auto tpm2_hash = dynamic_cast<HashFunction*>(m_hash.get())) {
            // Use the TPM2 hash object to get the validation ticket.
            return tpm2_hash->final_with_ticket();
         }

         // No validation ticket for software hashes.
         // TODO: Make this prettier
         unique_esys_ptr<TPM2B_DIGEST> digest(new TPM2B_DIGEST(init_empty<TPM2B_DIGEST>()));
         copy_into<TPM2B_DIGEST>(*digest, m_hash->final_stdvec());

         unique_esys_ptr<TPMT_TK_HASHCHECK> dummy_validation(new TPMT_TK_HASHCHECK(
            {.tag = TPM2_ST_HASHCHECK, .hierarchy = TPM2_RH_NULL, .digest = init_empty<TPM2B_DIGEST>()}));

         return {std::move(digest), std::move(dummy_validation)};
      }

      std::string name() const { return m_hash->name(); }

      TPMI_ALG_HASH type() const { return get_tpm2_hash_type(m_hash->name()); }

   private:
      HashFunctionWrapper(std::unique_ptr<Botan::HashFunction> hash) : m_hash(std::move(hash)) {}

   private:
      std::unique_ptr<Botan::HashFunction> m_hash;
};

TPMT_SIG_SCHEME select_tpmt_sig_scheme(std::string_view padding) {
   const auto [name, hash] = schemes_from_padding(padding);

   const auto scheme = [&]() -> TPMI_ALG_SIG_SCHEME {
      if(name == "EMSA_PKCS1" || name == "PKCS1v15" || name == "EMSA-PKCS1-v1_5" || name == "EMSA3") {
         return TPM2_ALG_RSASSA;
      }

      if(name == "PSS" || name == "PSSR" || name == "EMSA-PSS" || name == "PSS-MGF1" || name == "EMSA4") {
         if(SCAN_Name(padding).arg_count() != 1) {
            throw Not_Implemented("RSA signing using PSS with MGF1");
         }
         return TPM2_ALG_RSAPSS;
      }

      throw Not_Implemented("RSA signing with padding scheme " + name);
   }();

   return {TPMT_SIG_SCHEME{
      .scheme = scheme,
      .details = {.any = {.hashAlg = get_tpm2_hash_type(hash)}},
   }};
}

HashFunctionWrapper select_hash_for_signing(const Object& handle,
                                            const SessionBundle& sessions,
                                            std::string_view padding) {
   // When signing, we have to hash in the TPM if the key is restricted.
   // Otherwise, we can hash in software. In this function we create a
   // HashFunctionWrapper that hashes in hardware if and only if
   // the key is restricted.
   const auto& pubinfo = handle._public_info(sessions);

   // Restricted keys require to provide the hash validation ticket that is
   // provided when hashing the data to sign on the TPM under a specific
   // hierarchy.
   const bool is_restricted = pubinfo.pub->publicArea.objectAttributes & TPMA_OBJECT_RESTRICTED;

   const auto hash = schemes_from_padding(padding).second;

   if(is_restricted) {
      // For restricted keys, we have to use the validation ticket from a TPM created hash

      // TODO: this could also be ENDORSEMENT or PLATFORM, and we're not 100% sure
      //       that OWNER is always the right choice here.
      const TPMI_RH_HIERARCHY hierarchy = ESYS_TR_RH_OWNER;
      BOTAN_ASSERT(hierarchy != ESYS_TR_RH_NULL, "NULL hierarchy for validation not possible with restricted key");

      return HashFunctionWrapper::create_with_hashing_in_tpm(handle.context(), hash, hierarchy, sessions);
   } else {
      return HashFunctionWrapper::create_with_hashing_in_software(hash);
   }
}

Object make_persistent_object(const std::shared_ptr<Context>& ctx,
                              uint32_t persistent_object_handle,
                              std::span<const uint8_t> auth_value,
                              const SessionBundle& sessions) {
   BOTAN_ARG_CHECK(
      TPM2_PERSISTENT_FIRST <= persistent_object_handle && persistent_object_handle <= TPM2_PERSISTENT_LAST,
      "persistent_object_handle out of range");
   const bool is_persistent = ctx->in_persistent_handles(persistent_object_handle);
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

RSA_PrivateKey::CreationData create_transient_key(const std::shared_ptr<Context>& ctx,
                                                  const RSA_PrivateKey& parent,
                                                  std::span<const uint8_t> auth_value,
                                                  const SessionBundle& sessions,
                                                  uint16_t keylength,
                                                  uint32_t exponent) {
   // TODO: Figure out how to use this properly. The Architecture Document
   //       states that the key derivation incorporates the data in both
   //       sensitive.sensitive.data and in public_template.unique.rsa.
   //
   // See Section 28.2 here:
   // https://trustedcomputinggroup.org/wp-content/uploads/TCG_TPM2_r1p59_Part1_Architecture_pub.pdf
   TPM2B_SENSITIVE_CREATE sensitive = {
      .size = 0,
      .sensitive =
         {
            .userAuth = copy_into<TPM2B_AUTH>(auth_value),
            .data = init_empty<TPM2B_SENSITIVE_DATA>(),
         },
   };

   TPMT_PUBLIC public_template = {
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
                  .exponent = exponent,
               },
         },
      // TODO: perhaps fill this somehow: see above...
      .unique = {.rsa = init_empty<TPM2B_PUBLIC_KEY_RSA>()},
   };

   TPM2B_TEMPLATE generation_template = {};
   size_t offset = 0;
   check_rc("Tss2_MU_TPMT_PUBLIC_Marshal",
            Tss2_MU_TPMT_PUBLIC_Marshal(&public_template, generation_template.buffer, sizeof(TPMT_PUBLIC), &offset));
   generation_template.size = offset;

   unique_esys_ptr<TPM2B_PRIVATE> private_bytes;
   unique_esys_ptr<TPM2B_PUBLIC> public_info;

   Object handle(ctx);
   check_rc("Esys_CreateLoaded",
            Esys_CreateLoaded(inner(ctx),
                              parent.handles().transient_handle(),
                              sessions[0],
                              sessions[1],
                              sessions[2],
                              &sensitive,
                              &generation_template,
                              out_transient_handle(handle),
                              out_ptr(private_bytes),
                              out_ptr(public_info)));
   BOTAN_ASSERT_NONNULL(private_bytes);
   BOTAN_ASSERT_NOMSG(public_info->publicArea.type == TPM2_ALG_RSA);
   BOTAN_ASSERT_NOMSG(handle.has_transient_handle());

   return {
      .handle = std::move(handle),
      .private_blob = copy_into<std::vector<uint8_t>>(*private_bytes),
      .public_key = rsa_pubkey_from_tss2_public(public_info.get()),
   };
}

}  // namespace

std::unique_ptr<RSA_PublicKey> RSA_PublicKey::from_persistent(const std::shared_ptr<Context>& ctx,
                                                              uint32_t persistent_object_handle,
                                                              const SessionBundle& sessions) {
   return std::unique_ptr<RSA_PublicKey>(
      new RSA_PublicKey(make_persistent_object(ctx, persistent_object_handle, {}, sessions), sessions));
}

RSA_PrivateKey::RSA_PrivateKey(const std::shared_ptr<Context>& ctx,
                               const RSA_PrivateKey& parent,
                               std::span<const uint8_t> auth_value,
                               const SessionBundle& sessions,
                               uint16_t keylength,
                               std::optional<uint32_t> exponent) :
      RSA_PrivateKey(
         create_transient_key(ctx, parent, auth_value, sessions, keylength, exponent.value_or(0 /* TPM's default */)),
         sessions) {}

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

RSA_PrivateKey::RSA_PrivateKey(Object object, SessionBundle sessions) :
      Botan::RSA_PublicKey(rsa_pubkey_from_tss2_public(object._public_info(sessions, TPM2_ALG_RSA).pub.get())),
      m_handle(std::move(object)),
      m_sessions(std::move(sessions)) {}

RSA_PrivateKey::RSA_PrivateKey(RSA_PrivateKey::CreationData data, SessionBundle sessions) :
      Botan::RSA_PublicKey(std::move(data.public_key)),
      m_handle(std::move(data.handle)),
      m_sessions(std::move(sessions)),
      m_private_blob(std::move(data.private_blob)) {}

namespace {

class RSA_Signature_Operation : public PK_Ops::Signature {
   private:
      RSA_Signature_Operation(const Object& object,
                              const SessionBundle& sessions,
                              TPMT_SIG_SCHEME scheme,
                              HashFunctionWrapper hash) :
            m_key_handle(object), m_sessions(sessions), m_scheme(scheme), m_hash(std::move(hash)) {}

   public:
      RSA_Signature_Operation(const Object& object, const SessionBundle& sessions, std::string_view padding) :
            RSA_Signature_Operation(
               object, sessions, select_tpmt_sig_scheme(padding), select_hash_for_signing(object, sessions, padding)) {}

      void update(std::span<const uint8_t> msg) override { m_hash.update(msg); }

      std::vector<uint8_t> sign(RandomNumberGenerator& /* rng */) override {
         auto [digest, validation] = m_hash.final_with_ticket();

         unique_esys_ptr<TPMT_SIGNATURE> signature;
         check_rc("Esys_Sign",
                  Esys_Sign(inner(m_key_handle.context()),
                            m_key_handle.transient_handle(),
                            m_sessions[0],
                            m_sessions[1],
                            m_sessions[2],
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
         return m_key_handle._public_info(m_sessions, TPM2_ALG_RSA).pub->publicArea.parameters.rsaDetail.keyBits / 8;
      }

      std::string hash_function() const override { return m_hash.name(); }

   private:
      const Object& m_key_handle;
      const SessionBundle& m_sessions;
      TPMT_SIG_SCHEME m_scheme;
      HashFunctionWrapper m_hash;
};

class RSA_Verification_Operation : public PK_Ops::Verification {
   private:
      RSA_Verification_Operation(const Object& object,
                                 const SessionBundle& sessions,
                                 TPMT_SIG_SCHEME scheme,
                                 HashFunctionWrapper hash) :
            m_key_handle(object), m_sessions(sessions), m_scheme(scheme), m_hash(std::move(hash)) {}

   public:
      /// Verification using a TPM2 key (Hashing performed in software)
      RSA_Verification_Operation(const Object& object, const SessionBundle& sessions, std::string_view padding) :
            RSA_Verification_Operation(
               object,
               sessions,
               select_tpmt_sig_scheme(padding),
               HashFunctionWrapper::create_with_hashing_in_software(schemes_from_padding(padding).second)) {}

      void update(std::span<const uint8_t> msg) override { m_hash.update(msg); }

      bool is_valid_signature(std::span<const uint8_t> sig_data) override {
         auto [digest, validation] = m_hash.final_with_ticket();

         const auto signature = [&]() -> TPMT_SIGNATURE {
            TPMT_SIGNATURE sig;
            sig.sigAlg = m_scheme.scheme;
            sig.signature.any.hashAlg = m_hash.type();

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
                                                                                    digest.get(),
                                                                                    &signature,
                                                                                    nullptr /* validation */));

         return rc == TPM2_RC_SUCCESS;
      }

      std::string hash_function() const override { return m_hash.name(); }

   private:
      const Object& m_key_handle;
      const SessionBundle& m_sessions;
      TPMT_SIG_SCHEME m_scheme;
      HashFunctionWrapper m_hash;
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
