/*
* TPM 2 Keys
* (C) 2024 Jack Lloyd
* (C) 2024 René Meusel, Amos Treiber - Rohde & Schwarz Cybersecurity GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/tpm2_keys.h>

#include <botan/internal/tpm2_util.h>

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
                                   .scheme = {.scheme = TPM2_ALG_RSASSA,
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

void TPM2_Key::create_new(uint32_t key_handle, const std::string& auth_val) {
   TPM2B_PRIVATE* out_private = nullptr;
   TPM2B_PUBLIC* out_public = nullptr;
   TPM2B_CREATION_DATA* creation_data = nullptr;
   TPM2B_DIGEST* creation_hash = nullptr;
   TPMT_TK_CREATION* creation_ticket = nullptr;

   TPM2B_DATA outside_info = {.size = 0, .buffer = {0}};
   TPML_PCR_SELECTION creation_pcr = {.count = 0};

   const auto in_sensitive = in_sensitive_from_auth_val(auth_val);

   // Create the signing key
   check_tss2_rc("Esys_Create",
                 Esys_Create(inner(m_ctx),
                             m_ctx->spk_handle(),
                             m_ctx->inner_session_object(),
                             ESYS_TR_NONE,
                             ESYS_TR_NONE,
                             &in_sensitive,
                             &rsa_sign_template,
                             &outside_info,
                             &creation_pcr,
                             &out_private,
                             &out_public,
                             &creation_data,
                             &creation_hash,
                             &creation_ticket));

   // Load the signing key
   check_tss2_rc("Esys_Load",
                 Esys_Load(inner(m_ctx),
                           m_ctx->spk_handle(),
                           m_ctx->inner_session_object(),
                           ESYS_TR_NONE,
                           ESYS_TR_NONE,
                           out_private,
                           out_public,
                           &m_transient_key_handle));

   // Authenticate it via authVal
   check_tss2_rc("Esys_TR_SetAuth",
                 Esys_TR_SetAuth(inner(m_ctx), m_transient_key_handle, &in_sensitive.sensitive.userAuth));

   // Make the key persistent
   ESYS_TR persistent_handle_out = ESYS_TR_NONE;  // Does not need to be flushed

   check_tss2_rc("Esys_EvictControl",
                 Esys_EvictControl(inner(m_ctx),
                                   ESYS_TR_RH_OWNER,
                                   m_transient_key_handle,
                                   m_ctx->inner_session_object(),
                                   ESYS_TR_NONE,
                                   ESYS_TR_NONE,
                                   key_handle,
                                   &persistent_handle_out));

   check_tss2_rc("Esys_TR_GetTpmHandle",
                 Esys_TR_GetTpmHandle(inner(m_ctx), persistent_handle_out, &m_persistent_key_handle));

   // Free resources we don't need anymore
   Esys_Free(out_private);
   Esys_Free(out_public);
   Esys_Free(creation_data);
   Esys_Free(creation_hash);
   Esys_Free(creation_ticket);
}

void TPM2_Key::load_existing(uint32_t key_handle, const std::string& auth_val) {
   // Load the key
   check_tss2_rc(
      "Esys_TR_FromTPMPublic",
      Esys_TR_FromTPMPublic(
         inner(m_ctx), key_handle, m_ctx->inner_session_object(), ESYS_TR_NONE, ESYS_TR_NONE, &m_transient_key_handle));

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

std::unique_ptr<Public_Key> TPM2_Key::public_key() const {
   throw Not_Implemented("TPM2_Key::public_key");  //TODO: Implement
}

size_t TPM2_Key::estimated_strength() const {
   return rsa_sign_template.publicArea.parameters.rsaDetail.keyBits;  //TODO: Update
}

size_t TPM2_Key::key_length() const {
   return rsa_sign_template.publicArea.parameters.rsaDetail.keyBits;  //TODO: Update
}

AlgorithmIdentifier TPM2_Key::algorithm_identifier() const {
   throw Not_Implemented("TPM2_Key::algorithm_identifier");  //TODO: Implement
}

std::vector<uint8_t> TPM2_Key::public_key_bits() const {
   throw Not_Implemented("TPM2_Key::public_key_bits");  //TODO: Implement
}

std::vector<uint8_t> TPM2_Key::raw_public_key_bits() const {
   throw Not_Implemented("TPM2_Key::raw_public_key_bits");  //TODO: Implement
}

secure_vector<uint8_t> TPM2_Key::private_key_bits() const {
   throw Not_Implemented("TPM2_Key::private_key_bits");  //TODO: Implement
}

bool TPM2_Key::check_key(RandomNumberGenerator& rng, bool) const {
   BOTAN_UNUSED(rng);
   throw Not_Implemented("TPM2_Key::check_key");  //TODO
}

std::unique_ptr<PK_Ops::Signature> TPM2_Key::create_signature_op(RandomNumberGenerator& rng,
                                                                 std::string_view params,
                                                                 std::string_view provider) const {
   throw Not_Implemented("TPM2_Key::create_signature_op");  //TODO
}

}  // namespace Botan
