/*
* TPM 2.0 Base Object handling
* (C) 2024 Jack Lloyd
* (C) 2024 René Meusel, Amos Treiber - Rohde & Schwarz Cybersecurity GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/tpm2_object.h>

#include <botan/tpm2_session.h>

#include <botan/internal/stl_util.h>
#include <botan/internal/tpm2_util.h>

#include <tss2/tss2_esys.h>

namespace Botan::TPM2 {

namespace {

using ObjectAttributesWrapper =
   AttributeWrapper<TPMA_OBJECT,
                    ObjectAttributes,
                    {&ObjectAttributes::fixed_tpm, TPMA_OBJECT_FIXEDTPM},
                    {&ObjectAttributes::st_clear, TPMA_OBJECT_STCLEAR},
                    {&ObjectAttributes::fixed_parent, TPMA_OBJECT_FIXEDPARENT},
                    {&ObjectAttributes::sensitive_data_origin, TPMA_OBJECT_SENSITIVEDATAORIGIN},
                    {&ObjectAttributes::user_with_auth, TPMA_OBJECT_USERWITHAUTH},
                    {&ObjectAttributes::admin_with_policy, TPMA_OBJECT_ADMINWITHPOLICY},
                    {&ObjectAttributes::no_da, TPMA_OBJECT_NODA},
                    {&ObjectAttributes::encrypted_duplication, TPMA_OBJECT_ENCRYPTEDDUPLICATION},
                    {&ObjectAttributes::restricted, TPMA_OBJECT_RESTRICTED},
                    {&ObjectAttributes::decrypt, TPMA_OBJECT_DECRYPT},
                    {&ObjectAttributes::sign_encrypt, TPMA_OBJECT_SIGN_ENCRYPT},
                    {&ObjectAttributes::x509sign, TPMA_OBJECT_X509SIGN}>;

}  // namespace

ObjectAttributes ObjectAttributes::read(TPMA_OBJECT attributes) {
   return ObjectAttributesWrapper::read(attributes);
}

TPMA_OBJECT ObjectAttributes::render(ObjectAttributes attributes) {
   return ObjectAttributesWrapper::render(attributes);
}

Object::Object(std::shared_ptr<Context> ctx) : m_ctx(std::move(ctx)), m_handles(std::make_unique<ObjectHandles>()) {}

Object::~Object() {
   if(m_handles) {
      flush();
   }
}

Object::Object(Object&& other) noexcept :
      m_ctx(std::move(other.m_ctx)),
      m_handles(std::move(other.m_handles)),
      m_public_info(std::move(other.m_public_info)) {
   other.scrub();
}

Object& Object::operator=(Object&& other) noexcept {
   if(this != &other) {
      flush();
      m_ctx = std::move(other.m_ctx);
      m_handles = std::move(other.m_handles);
      m_public_info = std::move(other.m_public_info);
      other.scrub();
   }
   return *this;
}

/// Flush the object's TPM handles as necessary
void Object::flush() const noexcept {
   // Only purely transient objects have to be flushed
   if(has_transient_handle()) {
      if(has_persistent_handle()) {
         Esys_TR_Close(inner(m_ctx), &m_handles->transient);
      } else {
         Esys_FlushContext(inner(m_ctx), m_handles->transient);
      }
   }
}

/// Destroy the object's internal state, making the destructor a no-op.
void Object::scrub() {
   m_ctx.reset();
   m_handles.reset();
   m_public_info.reset();
}

/// Flush the object's TPM handles and reset its internal state
void Object::_reset() noexcept {
   flush();
   _disengage();
}

/// Reset the object's internal state without flushing its TPM handles
void Object::_disengage() noexcept {
   m_handles = std::make_unique<ObjectHandles>();
   m_public_info.reset();
}

bool Object::has_persistent_handle() const {
   return m_handles->persistent.has_value();
}

bool Object::has_transient_handle() const {
   return m_handles->transient != ESYS_TR_NONE;
}

uint32_t Object::persistent_handle() const {
   BOTAN_STATE_CHECK(has_persistent_handle());
   static_assert(std::same_as<decltype(m_handles->persistent)::value_type, uint32_t>);
   return *m_handles->persistent;
}

uint32_t Object::transient_handle() const noexcept {
   static_assert(std::same_as<decltype(m_handles->transient), uint32_t>);
   return m_handles->transient;
}

ObjectAttributes Object::attributes(const SessionBundle& sessions) const {
   const auto attrs = _public_info(sessions).pub->publicArea.objectAttributes;
   return ObjectAttributes::read(attrs);
}

PublicInfo& Object::_public_info(const SessionBundle& sessions, std::optional<uint32_t> expected_type) const {
   if(!m_public_info) {
      m_public_info = std::make_unique<PublicInfo>();

      check_rc("Esys_ReadPublic",
               Esys_ReadPublic(inner(m_ctx),
                               m_handles->transient,
                               sessions[0],
                               sessions[1],
                               sessions[2],
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

ObjectHandles& Object::handles() {
   return *m_handles;
}

}  // namespace Botan::TPM2
