/*
* TPM 2.0 Base Object handling
* (C) 2024 Jack Lloyd
* (C) 2024 René Meusel, Amos Treiber - Rohde & Schwarz Cybersecurity GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/tpm2_object.h>

#include <botan/internal/stl_util.h>
#include <botan/internal/tpm2_util.h>

#include <tss2/tss2_esys.h>

namespace Botan::TPM2 {

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

}  // namespace Botan::TPM2
