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

PublicInfo& Object::_public_info(std::optional<uint32_t> expected_type) const {
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

      if(expected_type) {
         BOTAN_STATE_CHECK(m_public_info->pub->publicArea.type == *expected_type);
      }
   }

   return *m_public_info;
}

Object::Object(std::shared_ptr<Context> ctx) : m_ctx(std::move(ctx)), m_handles(std::make_unique<ObjectHandles>()) {}

Object::~Object() {
   if(m_handles) {
      if(!m_handles->persistent) {
         check_tss2_rc("Esys_FlushContext", Esys_FlushContext(inner(m_ctx), m_handles->transient));
      }

      // No need to flush persistent handles
   }
}

Object::Object(Object&& other) noexcept :
      m_ctx(std::move(other.m_ctx)),
      m_handles(std::move(other.m_handles)),
      m_public_info(std::move(other.m_public_info)) {
   other.m_handles.reset();
   other.m_public_info.reset();
}

Object& Object::operator=(Object&& other) noexcept {
   if(this != &other) {
      m_ctx = std::move(other.m_ctx);
      m_handles = std::move(other.m_handles);
      m_public_info = std::move(other.m_public_info);
      other.m_handles.reset();
      other.m_public_info.reset();
   }
   return *this;
}

uint32_t Object::persistent_handle() const {
   BOTAN_STATE_CHECK(is_persistent());
   return *m_handles->persistent;
}

uint32_t Object::transient_handle() const {
   return m_handles->transient;
}

ObjectHandles& Object::handles() {
   return *m_handles;
}

}  // namespace Botan::TPM2
