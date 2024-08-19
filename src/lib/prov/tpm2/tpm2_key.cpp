/*
* TPM 2.0 Key Wrappers' Base Class
* (C) 2024 Jack Lloyd
* (C) 2024 René Meusel, Amos Treiber - Rohde & Schwarz Cybersecurity GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/tpm2_key.h>

#include <botan/tpm2_rsa.h>

#include <botan/internal/fmt.h>
#include <botan/internal/stl_util.h>
#include <botan/internal/tpm2_algo_mappings.h>
#include <botan/internal/tpm2_hash.h>
#include <botan/internal/tpm2_util.h>

#include <tss2/tss2_esys.h>
#include <tss2/tss2_mu.h>

namespace Botan::TPM2 {

namespace {

Object load_persistent_object(const std::shared_ptr<Context>& ctx,
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

   const auto key_type = object._public_info(sessions).pub->publicArea.type;
   BOTAN_ARG_CHECK(key_type == TPM2_ALG_RSA || key_type == TPM2_ALG_ECC,
                   "persistent object is neither RSA nor ECC public key");

   return object;
}

}  // namespace

std::unique_ptr<PrivateKey> PrivateKey::create_transient_from_template(const std::shared_ptr<Context>& ctx,
                                                                       SessionBundle sessions,
                                                                       const TPM2::PrivateKey& parent,
                                                                       const TPMT_PUBLIC* key_template,
                                                                       const TPM2B_SENSITIVE_CREATE* sensitive_data) {
   BOTAN_ARG_CHECK(key_template->type == TPM2_ALG_RSA || key_template->type == TPM2_ALG_ECC,
                   "key_template is neither RSA nor ECC");

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
   BOTAN_ASSERT_NOMSG(public_info->publicArea.type == key_template->type);
   BOTAN_ASSERT_NOMSG(handle.has_transient_handle());

   if(key_template->type == TPM2_ALG_RSA) {
      return std::unique_ptr<RSA_PrivateKey>(
         new RSA_PrivateKey(std::move(handle), std::move(sessions), public_info.get(), as_span(*private_bytes)));
   } else {
      throw Not_Implemented("TPM2-based ECC keys are not yet supported");
   }
}

std::unique_ptr<PublicKey> PublicKey::from_persistent(const std::shared_ptr<Context>& ctx,
                                                      uint32_t persistent_object_handle,
                                                      SessionBundle sessions) {
   auto handles = load_persistent_object(ctx, persistent_object_handle, {}, sessions);

   const auto* pubinfo = handles._public_info(sessions).pub.get();
   if(pubinfo->publicArea.type == TPM2_ALG_RSA) {
      return std::unique_ptr<PublicKey>(new RSA_PublicKey(std::move(handles), std::move(sessions), pubinfo));
   } else {
      throw Not_Implemented("TPM2-based ECC keys are not yet supported");
   }
}

std::unique_ptr<PrivateKey> PrivateKey::from_persistent(const std::shared_ptr<Context>& ctx,
                                                        uint32_t persistent_object_handle,
                                                        std::span<const uint8_t> auth_value,
                                                        SessionBundle sessions) {
   auto handles = load_persistent_object(ctx, persistent_object_handle, auth_value, sessions);

   const auto* pubinfo = handles._public_info(sessions).pub.get();
   if(pubinfo->publicArea.type == TPM2_ALG_RSA) {
      return std::unique_ptr<RSA_PrivateKey>(new RSA_PrivateKey(std::move(handles), std::move(sessions), pubinfo));
   } else {
      throw Not_Implemented("TPM2-based ECC keys are not yet supported");
   }
}

}  // namespace Botan::TPM2
