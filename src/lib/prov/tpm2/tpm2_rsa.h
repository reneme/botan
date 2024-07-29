/*
* TPM 2.0 RSA Key Wrappers
* (C) 2024 Jack Lloyd
* (C) 2024 René Meusel, Amos Treiber - Rohde & Schwarz Cybersecurity GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/
#ifndef BOTAN_TPM2_RSA_H_
#define BOTAN_TPM2_RSA_H_

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

class BOTAN_PUBLIC_API(3, 6) RSA_PublicKey : public virtual Object,
                                             public virtual Botan::RSA_PublicKey {
   public:
      RSA_PublicKey(std::shared_ptr<Context> ctx,
                    uint32_t persistent_object_handle,
                    std::span<const uint8_t> auth_value);

      virtual ~RSA_PublicKey() = default;
      RSA_PublicKey(const RSA_PublicKey&) = delete;
      RSA_PublicKey& operator=(const RSA_PublicKey&) = delete;
      RSA_PublicKey(RSA_PublicKey&& other) noexcept = default;
      RSA_PublicKey& operator=(RSA_PublicKey&& other) noexcept = default;

      std::unique_ptr<Private_Key> generate_another(RandomNumberGenerator&) const override {
         throw Not_Implemented("Cannot generate a new TPM-based keypair from this asymmetric key");
      }

      bool supports_operation(PublicKeyOperation op) const override {
         return op == PublicKeyOperation::Signature || op == PublicKeyOperation::Encryption ||
                op == PublicKeyOperation::KeyEncapsulation;
      }

   protected:
      uint32_t expected_public_info_type() const final;
};

BOTAN_DIAGNOSTIC_PUSH
BOTAN_DIAGNOSTIC_IGNORE_INHERITED_VIA_DOMINANCE

class BOTAN_PUBLIC_API(3, 6) RSA_PrivateKey final : public virtual Object,
                                                    public virtual Botan::RSA_PublicKey,
                                                    public virtual Private_Key {
   public:
      RSA_PrivateKey(std::shared_ptr<Context> ctx,
                     uint32_t persistent_object_handle,
                     std::span<const uint8_t> auth_value);
      virtual ~RSA_PrivateKey() = default;
      RSA_PrivateKey(const RSA_PrivateKey&) = delete;
      RSA_PrivateKey& operator=(const RSA_PrivateKey&) = delete;
      RSA_PrivateKey(RSA_PrivateKey&& other) noexcept = default;
      RSA_PrivateKey& operator=(RSA_PrivateKey&& other) noexcept = default;

      std::unique_ptr<Public_Key> public_key() const override;

      secure_vector<uint8_t> private_key_bits() const override {
         throw Not_Implemented("cannot export private key bits from a TPM2 key");
      }

      std::unique_ptr<PK_Ops::Signature> create_signature_op(RandomNumberGenerator& rng,
                                                             std::string_view params,
                                                             std::string_view provider) const override;

   protected:
      uint32_t expected_public_info_type() const final;
};

BOTAN_DIAGNOSTIC_POP

}  // namespace Botan::TPM2

#endif
