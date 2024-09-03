/*
* TPM 2.0 Base Object handling
* (C) 2024 Jack Lloyd
* (C) 2024 René Meusel, Amos Treiber - Rohde & Schwarz Cybersecurity GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_TPM2_BASE_OBJECT_H_
#define BOTAN_TPM2_BASE_OBJECT_H_

#include <botan/tpm2_context.h>

namespace Botan::TPM2 {

struct PublicInfo;
struct ObjectHandles;
class ObjectSetter;
class SessionBundle;

using TPMA_OBJECT = uint32_t;

/**
 * See TPM 2.0 Part 2, Section 8.3.2
 */
struct ObjectAttributes {
      static ObjectAttributes read(TPMA_OBJECT attributes);
      static TPMA_OBJECT render(ObjectAttributes attributes);

      bool fixed_tpm = false;
      bool st_clear = false;
      bool fixed_parent = false;
      bool sensitive_data_origin = false;
      bool user_with_auth = false;
      bool admin_with_policy = false;
      bool no_da = false;
      bool encrypted_duplication = false;
      bool restricted = false;
      bool decrypt = false;
      bool sign_encrypt = false;
      bool x509sign = false;
};

class BOTAN_PUBLIC_API(3, 6) Object {
   public:
      Object(std::shared_ptr<Context> ctx);

      virtual ~Object();
      Object(const Object&) = delete;
      Object& operator=(const Object&) = delete;
      Object(Object&& other) noexcept;
      Object& operator=(Object&& other) noexcept;

      const std::shared_ptr<Context>& context() const { return m_ctx; }

      bool has_persistent_handle() const;
      bool has_transient_handle() const;

      uint32_t persistent_handle() const;
      uint32_t transient_handle() const noexcept;

      ObjectAttributes attributes(const SessionBundle& sessions) const;

      void _reset() noexcept;
      void _disengage() noexcept;
      PublicInfo& _public_info(const SessionBundle& sessions, std::optional<uint32_t> expected_type = {}) const;

   private:
      friend class ObjectSetter;
      ObjectHandles& handles();

      void flush() const noexcept;
      void scrub();

   private:
      std::shared_ptr<Context> m_ctx;
      std::unique_ptr<ObjectHandles> m_handles;
      mutable std::unique_ptr<PublicInfo> m_public_info;
};

}  // namespace Botan::TPM2

#endif
