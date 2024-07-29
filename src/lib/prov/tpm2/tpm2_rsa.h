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
#include <botan/tpm2_object.h>

namespace Botan::TPM2 {

struct PublicInfo;
struct ObjectHandles;

class BOTAN_PUBLIC_API(3, 6) RSA_PublicKey : public Botan::RSA_PublicKey {
   public:
      static RSA_PublicKey from_persistent(const std::shared_ptr<Context>& ctx,
                                           uint32_t persistent_object_handle,
                                           std::span<const uint8_t> auth_value);

   public:
      ~RSA_PublicKey() override = default;
      RSA_PublicKey(const RSA_PublicKey&) = delete;
      RSA_PublicKey& operator=(const RSA_PublicKey&) = delete;
      RSA_PublicKey(RSA_PublicKey&& other) noexcept = default;
      RSA_PublicKey& operator=(RSA_PublicKey&& other) noexcept = default;

      std::unique_ptr<Private_Key> generate_another(RandomNumberGenerator&) const override {
         throw Not_Implemented("Cannot generate a new TPM-based keypair from this asymmetric key");
      }

      const Object& handles() const { return m_handle; }

      std::unique_ptr<PK_Ops::Verification> create_verification_op(std::string_view params,
                                                                   std::string_view provider) const override;

   protected:
      RSA_PublicKey(Object object);

   private:
      Object m_handle;
};

BOTAN_DIAGNOSTIC_PUSH
BOTAN_DIAGNOSTIC_IGNORE_INHERITED_VIA_DOMINANCE

class BOTAN_PUBLIC_API(3, 6) RSA_PrivateKey final : public virtual Botan::RSA_PublicKey,
                                                    public virtual Private_Key {
   public:
      static RSA_PrivateKey from_persistent(const std::shared_ptr<Context>& ctx,
                                            uint32_t persistent_object_handle,
                                            std::span<const uint8_t> auth_value);

   public:
      ~RSA_PrivateKey() override = default;
      RSA_PrivateKey(const RSA_PrivateKey&) = delete;
      RSA_PrivateKey& operator=(const RSA_PrivateKey&) = delete;
      RSA_PrivateKey(RSA_PrivateKey&& other) noexcept = default;
      RSA_PrivateKey& operator=(RSA_PrivateKey&& other) noexcept = default;

      std::unique_ptr<Public_Key> public_key() const override;

      secure_vector<uint8_t> private_key_bits() const override {
         throw Not_Implemented("cannot export private key bits from a TPM2 key");
      }

      const Object& handles() const { return m_handle; }

      std::unique_ptr<PK_Ops::Signature> create_signature_op(RandomNumberGenerator& rng,
                                                             std::string_view params,
                                                             std::string_view provider) const override;

   protected:
      RSA_PrivateKey(Object obj);

   private:
      Object m_handle;
};

BOTAN_DIAGNOSTIC_POP

}  // namespace Botan::TPM2

#endif
