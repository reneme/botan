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
#include <botan/internal/ct_utils.h>  // TODO: remove me
#include <botan/internal/emsa.h>
#include <botan/internal/fmt.h>
#include <botan/internal/scan_name.h>
#include <botan/internal/stl_util.h>
#include <botan/internal/tpm2_util.h>
#include <botan/internal/workfactor.h>

#include <tss2/tss2_esys.h>

namespace Botan::TPM2 {

namespace {

template <typename T>
concept tpm2_buffer = requires(T t) {
   { t.buffer } -> std::convertible_to<const uint8_t*>;
   { t.size } -> std::convertible_to<size_t>;
};

auto as_span(tpm2_buffer auto& data) {
   return std::span{data.buffer, data.size};
}

template <tpm2_buffer T>
T copy_into(std::span<const uint8_t> data) {
   T result;
   BOTAN_ASSERT_NOMSG(data.size() <= sizeof(result.buffer));
   result.size = static_cast<decltype(result.size)>(data.size());
   copy_mem(as_span(result), data);
   return result;
}

template <concepts::resizable_byte_buffer OutT>
OutT copy_into(const tpm2_buffer auto& data) {
   OutT result;
   result.resize(data.size);
   copy_mem(result, as_span(data));
   return result;
}

template <tpm2_buffer T>
T init_empty() {
   T result;
   result.size = 0;
   return result;
}

TPMI_ALG_HASH get_tpm2_hash_type(const std::optional<std::string>& hash_name) {
   if(!hash_name) {
      return TPM2_ALG_NULL;
   } else if(*hash_name == "SHA-1") {
      return TPM2_ALG_SHA1;
   } else if(*hash_name == "SHA-256") {
      return TPM2_ALG_SHA256;
   } else if(*hash_name == "SHA-384") {
      return TPM2_ALG_SHA384;
   } else if(*hash_name == "SHA-512") {
      return TPM2_ALG_SHA512;
   } else if(*hash_name == "SHA-3(256)") {
      return TPM2_ALG_SHA3_256;
   } else if(*hash_name == "SHA-3(384)") {
      return TPM2_ALG_SHA3_384;
   } else if(*hash_name == "SHA-3(512)") {
      return TPM2_ALG_SHA3_512;
   }

   throw Not_Implemented("TPM2 signing with hash " + *hash_name);
}

std::string_view get_tpm2_hash_name(TPMI_ALG_HASH hash_type) {
   switch(hash_type) {
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
      default:
         throw Invalid_Argument("unknown TPM2 hash algorithm: " + std::to_string(hash_type));
   }
}

TPMT_SIG_SCHEME prepare_padding_mechanism(std::string_view padding) {
   SCAN_Name req(padding);
   auto hash = [&]() -> std::optional<std::string> {
      if(req.arg_count() > 0) {
         return req.arg(0);
      } else {
         return std::nullopt;
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

   return {
      .scheme = scheme,
      .details = {.any = {.hashAlg = get_tpm2_hash_type(hash)}},
   };
}

template <typename T>
   requires std::is_default_constructible_v<T>
[[nodiscard]] constexpr auto out_opt(std::optional<T>& outopt) noexcept {
   class out_opt_t {
      public:
         constexpr ~out_opt_t() noexcept { m_opt = m_raw; }

         constexpr out_opt_t(std::optional<T>& outopt) noexcept : m_opt(outopt) {}

         out_opt_t(const out_opt_t&) = delete;
         out_opt_t(out_opt_t&&) = delete;
         out_opt_t& operator=(const out_opt_t&) = delete;
         out_opt_t& operator=(out_opt_t&&) = delete;

         [[nodiscard]] constexpr operator T*() && noexcept { return &m_raw; }

      private:
         std::optional<T>& m_opt;
         T m_raw;
   };

   return out_opt_t{outopt};
}

}  // namespace

struct PublicInfo {
      unique_esys_ptr<TPM2B_PUBLIC> pub;
      unique_esys_ptr<TPM2B_NAME> name;
      unique_esys_ptr<TPM2B_NAME> qualified_name;
};

struct ObjectHandles {
      std::optional<TPM2_HANDLE> persistent = std::nullopt;
      ESYS_TR transient = ESYS_TR_NONE;
};

bool Object::is_persistent() const {
   return m_handles->persistent.has_value();
}

PublicInfo& Object::public_info() const {
   if(!m_public_info) {
      m_public_info = std::make_unique<PublicInfo>();

      check_tss2_rc("Esys_ReadPublic",
                    Esys_ReadPublic(inner(m_ctx),
                                    m_handles->transient,
                                    m_ctx->session_handle(0),
                                    m_ctx->session_handle(1),
                                    m_ctx->session_handle(2),
                                    out_ptr(m_public_info->pub),
                                    out_ptr(m_public_info->name),
                                    out_ptr(m_public_info->qualified_name)));
      BOTAN_ASSERT_NONNULL(m_public_info->pub);
      BOTAN_STATE_CHECK(m_public_info->pub->publicArea.type == expected_public_info_type());
   }

   return *m_public_info;
}

Object::Object(std::shared_ptr<Context> ctx, uint32_t persistent_object_id, std::span<const uint8_t> auth_value) :
      m_ctx(std::move(ctx)), m_handles(std::make_unique<ObjectHandles>()) {
   BOTAN_ARG_CHECK(TPM2_PERSISTENT_FIRST <= persistent_object_id && persistent_object_id <= TPM2_PERSISTENT_LAST,
                   "persistent_object_id out of range");
   const bool is_persistent = m_ctx->in_persistent_handles(persistent_object_id);
   BOTAN_STATE_CHECK(is_persistent);

   check_tss2_rc("Esys_TR_FromTPMPublic",
                 Esys_TR_FromTPMPublic(inner(m_ctx),
                                       persistent_object_id,
                                       m_ctx->session_handle(0),
                                       m_ctx->session_handle(1),
                                       m_ctx->session_handle(2),
                                       &m_handles->transient));

   const auto user_auth = copy_into<TPM2B_AUTH>(auth_value);
   check_tss2_rc("Esys_TR_SetAuth", Esys_TR_SetAuth(inner(m_ctx), m_handles->transient, &user_auth));

   check_tss2_rc("Esys_TR_GetTpmHandle",
                 Esys_TR_GetTpmHandle(inner(m_ctx), m_handles->transient, out_opt(m_handles->persistent)));
}

Object::~Object() {
   if(!m_handles->persistent) {
      check_tss2_rc("Esys_FlushContext", Esys_FlushContext(inner(m_ctx), m_handles->transient));
   }

   // No need to flush persistent handles
}

Object::Object(Object&&) noexcept = default;
Object& Object::operator=(Object&&) noexcept = default;

uint32_t Object::persistent_handle() const {
   BOTAN_STATE_CHECK(is_persistent());
   return *m_handles->persistent;
}

uint32_t Object::transient_handle() const {
   return m_handles->transient;
}

namespace {

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

}  // namespace

RSA_PublicKey::RSA_PublicKey(std::shared_ptr<Context> ctx,
                             uint32_t persistent_object_handle,
                             std::span<const uint8_t> auth_value) :
      Object(std::move(ctx), persistent_object_handle, auth_value),
      Botan::RSA_PublicKey(n(public_info()), e(public_info())) {}

uint32_t RSA_PublicKey::expected_public_info_type() const {
   return TPM2_ALG_RSA;
}

RSA_PrivateKey::RSA_PrivateKey(std::shared_ptr<Context> ctx,
                               uint32_t persistent_object_handle,
                               std::span<const uint8_t> auth_value) :
      Object(std::move(ctx), persistent_object_handle, auth_value),
      Botan::RSA_PublicKey(n(public_info()), e(public_info())) {}

std::unique_ptr<Public_Key> RSA_PrivateKey::public_key() const {
   // TODO: Probably this should return an TPM2_RSA_PublicKey at one point
   return std::make_unique<Botan::RSA_PublicKey>(algorithm_identifier(), public_key_bits());
}

uint32_t RSA_PrivateKey::expected_public_info_type() const {
   return TPM2_ALG_RSA;
}

namespace {

class RSA_Signature_Operation : public PK_Ops::Signature {
   public:
      RSA_Signature_Operation(std::shared_ptr<Context> ctx, const RSA_PrivateKey& key, std::string_view padding) :
            m_ctx(std::move(ctx)),
            m_key(key),
            m_scheme(prepare_padding_mechanism(padding)),
            m_sequence_handle(ESYS_TR_NONE) {
         const auto noauth = init_empty<TPM2B_AUTH>();
         check_tss2_rc("Esys_HashSequenceStart",
                       Esys_HashSequenceStart(inner(m_ctx),
                                              m_ctx->session_handle(0),
                                              m_ctx->session_handle(1),
                                              m_ctx->session_handle(2),
                                              &noauth,
                                              m_scheme.details.any.hashAlg,
                                              &m_sequence_handle));
      }

      void update(std::span<const uint8_t> msg) override {
         BufferSlicer slicer(msg);
         while(slicer.remaining() > 0) {
            const size_t chunk = std::min(slicer.remaining(), size_t(TPM2_MAX_DIGEST_BUFFER));
            const auto data = copy_into<TPM2B_MAX_BUFFER>(slicer.take(chunk));
            check_tss2_rc("Esys_SequenceUpdate",
                          Esys_SequenceUpdate(inner(m_ctx),
                                              m_sequence_handle,
                                              m_ctx->session_handle(0),
                                              m_ctx->session_handle(1),
                                              m_ctx->session_handle(2),
                                              &data));
         }
         BOTAN_ASSERT_NOMSG(slicer.empty());
      }

      std::vector<uint8_t> sign(RandomNumberGenerator& /* rng */) override {
         unique_esys_ptr<TPMT_TK_HASHCHECK> validation;
         unique_esys_ptr<TPM2B_DIGEST> digest;

         const auto nodata = init_empty<TPM2B_MAX_BUFFER>();
         check_tss2_rc("Esys_SequenceComplete",
                       Esys_SequenceComplete(inner(m_ctx),
                                             m_sequence_handle,
                                             m_ctx->session_handle(0),
                                             m_ctx->session_handle(1),
                                             m_ctx->session_handle(2),
                                             &nodata,
                                             ESYS_TR_RH_NULL,
                                             out_ptr(digest),
                                             out_ptr(validation)));

         unique_esys_ptr<TPMT_SIGNATURE> signature;
         check_tss2_rc("Esys_Sign",
                       Esys_Sign(inner(m_ctx),
                                 m_key.transient_handle(),
                                 m_ctx->session_handle(0),
                                 m_ctx->session_handle(1),
                                 m_ctx->session_handle(2),
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

         BOTAN_ASSERT_NOMSG(sig.hash == m_scheme.details.any.hashAlg);

         return copy_into<std::vector<uint8_t>>(sig.sig);
      }

      size_t signature_length() const override { return m_key.key_length(); }

      std::string hash_function() const override {
         return std::string(get_tpm2_hash_name(m_scheme.details.any.hashAlg));
      }

   private:
      std::shared_ptr<Context> m_ctx;
      const RSA_PrivateKey& m_key;
      TPMT_SIG_SCHEME m_scheme;
      ESYS_TR m_sequence_handle;
};

class RSA_Verification_Operation : public PK_Ops::Verification {
   public:
      RSA_Verification_Operation(std::shared_ptr<Context> ctx, const RSA_PublicKey& key, std::string_view padding) :
            m_ctx(std::move(ctx)),
            m_key(key),
            m_scheme(prepare_padding_mechanism(padding)),
            m_sequence_handle(ESYS_TR_NONE) {
         const auto noauth = init_empty<TPM2B_AUTH>();
         check_tss2_rc("Esys_HashSequenceStart",
                       Esys_HashSequenceStart(inner(m_ctx),
                                              m_ctx->session_handle(0),
                                              m_ctx->session_handle(1),
                                              m_ctx->session_handle(2),
                                              &noauth,
                                              m_scheme.details.any.hashAlg,
                                              &m_sequence_handle));
      }

      void update(std::span<const uint8_t> msg) override {
         BufferSlicer slicer(msg);
         while(slicer.remaining() > 0) {
            const size_t chunk = std::min(slicer.remaining(), size_t(TPM2_MAX_DIGEST_BUFFER));
            const auto data = copy_into<TPM2B_MAX_BUFFER>(slicer.take(chunk));
            check_tss2_rc("Esys_SequenceUpdate",
                          Esys_SequenceUpdate(inner(m_ctx),
                                              m_sequence_handle,
                                              m_ctx->session_handle(0),
                                              m_ctx->session_handle(1),
                                              m_ctx->session_handle(2),
                                              &data));
         }
      }

      bool is_valid_signature(std::span<const uint8_t> sig) override {
         unique_esys_ptr<TPMT_TK_HASHCHECK> validation;
         unique_esys_ptr<TPM2B_DIGEST> digest;

         const auto nodata = init_empty<TPM2B_MAX_BUFFER>();
         check_tss2_rc("Esys_SequenceComplete",
                       Esys_SequenceComplete(inner(m_ctx),
                                             m_sequence_handle,
                                             m_ctx->session_handle(0),
                                             m_ctx->session_handle(1),
                                             m_ctx->session_handle(2),
                                             &nodata,
                                             ESYS_TR_RH_NULL,
                                             out_ptr(digest),
                                             out_ptr(validation)));

         const auto signature = [&]() -> TPMT_SIGNATURE {
            TPMT_SIGNATURE signature;
            signature.sigAlg = m_scheme.scheme;

            signature.signature.any.hashAlg = m_scheme.details.any.hashAlg;
            if(signature.sigAlg == TPM2_ALG_RSASSA) {
               signature.signature.rsassa.sig.size = sig.size();
               copy_mem(std::span{signature.signature.rsassa.sig.buffer, sig.size()}, sig);
               return signature;
            } else if(signature.sigAlg == TPM2_ALG_RSAPSS) {
               signature.signature.rsapss.sig.size = sig.size();
               copy_mem(std::span{signature.signature.rsapss.sig.buffer, sig.size()}, sig);
               return signature;
            }

            throw Invalid_State(fmt("Requested an unexpected signature scheme {}", signature.sigAlg));
         }();

         unique_esys_ptr<TPMT_TK_VERIFIED> result;
         const auto rc = Esys_VerifySignature(inner(m_ctx),
                                              m_key.transient_handle(),
                                              m_ctx->session_handle(0),
                                              m_ctx->session_handle(1),
                                              m_ctx->session_handle(2),
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

      std::string hash_function() const override {
         return std::string(get_tpm2_hash_name(m_scheme.details.any.hashAlg));
      }

   private:
      std::shared_ptr<Context> m_ctx;
      const RSA_PublicKey& m_key;
      TPMT_SIG_SCHEME m_scheme;
      ESYS_TR m_sequence_handle;
};

}  // namespace

std::unique_ptr<PK_Ops::Verification> RSA_PublicKey::create_verification_op(std::string_view params,
                                                                            std::string_view provider) const {
   BOTAN_UNUSED(provider);
   return std::make_unique<RSA_Verification_Operation>(context(), *this, params);
}

std::unique_ptr<PK_Ops::Signature> RSA_PrivateKey::create_signature_op(RandomNumberGenerator& rng,
                                                                       std::string_view params,
                                                                       std::string_view provider) const {
   BOTAN_UNUSED(rng);
   BOTAN_UNUSED(provider);
   return std::make_unique<RSA_Signature_Operation>(context(), *this, params);
}

}  // namespace Botan::TPM2
