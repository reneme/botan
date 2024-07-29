/*
* TPM 2.0 Base Object handling
* (C) 2024 Jack Lloyd
* (C) 2024 René Meusel, Amos Treiber - Rohde & Schwarz Cybersecurity GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_TPM2_BASE_OBJECT_H_
#define BOTAN_TPM2_BASE_OBJECT_H_

#include <botan/pk_keys.h>
#include <botan/rsa.h>
#include <botan/tpm2.h>

namespace Botan::TPM2 {

struct PublicInfo;
struct ObjectHandles;

class BOTAN_PUBLIC_API(3, 6) Object {
   public:
      Object(std::shared_ptr<Context> ctx, uint32_t persistent_object_handle, std::span<const uint8_t> auth_value);

      virtual ~Object();
      Object(const Object&) = delete;
      Object& operator=(const Object&) = delete;
      Object(Object&& other) noexcept;
      Object& operator=(Object&& other) noexcept;

      bool is_persistent() const;

      uint32_t persistent_handle() const;
      uint32_t transient_handle() const;

   protected:
      const std::shared_ptr<Context>& context() const { return m_ctx; }

      ObjectHandles& handles() const { return *m_handles; }

      PublicInfo& public_info() const;
      virtual uint32_t expected_public_info_type() const = 0;

   private:
      std::shared_ptr<Context> m_ctx;
      std::unique_ptr<ObjectHandles> m_handles;
      mutable std::unique_ptr<PublicInfo> m_public_info;
};
}  // namespace Botan::TPM2
#endif
