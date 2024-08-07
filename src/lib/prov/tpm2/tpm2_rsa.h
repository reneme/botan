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
#include <botan/tpm2_context.h>
#include <botan/tpm2_object.h>
#include <botan/tpm2_session.h>

namespace Botan::TPM2 {

struct PublicInfo;
struct ObjectHandles;

class BOTAN_PUBLIC_API(3, 6) RSA_PublicKey : public Botan::RSA_PublicKey {
   public:
      static std::unique_ptr<RSA_PublicKey> from_persistent(const std::shared_ptr<Context>& ctx,
                                                            uint32_t persistent_object_handle,
                                                            const SessionBundle& sessions = {});

   public:
      std::unique_ptr<Private_Key> generate_another(RandomNumberGenerator&) const override {
         throw Not_Implemented("Cannot generate a new TPM-based keypair from this asymmetric key");
      }

      const Object& handles() const { return m_handle; }

      std::unique_ptr<PK_Ops::Verification> create_verification_op(std::string_view params,
                                                                   std::string_view provider) const override;

   protected:
      RSA_PublicKey(Object object, SessionBundle sessions);

   private:
      Object m_handle;
      SessionBundle m_sessions;
};

BOTAN_DIAGNOSTIC_PUSH
BOTAN_DIAGNOSTIC_IGNORE_INHERITED_VIA_DOMINANCE

class BOTAN_PUBLIC_API(3, 6) RSA_PrivateKey final : public virtual Botan::RSA_PublicKey,
                                                    public virtual Private_Key {
   public:
      static std::unique_ptr<RSA_PrivateKey> from_persistent(const std::shared_ptr<Context>& ctx,
                                                             uint32_t persistent_object_handle,
                                                             std::span<const uint8_t> auth_value,
                                                             const SessionBundle& sessions);

      /**
       * Creates a new transient RSA key.
       */
      RSA_PrivateKey(const std::shared_ptr<Context>& ctx,
                     const RSA_PrivateKey& parent,
                     std::span<const uint8_t> auth_value,
                     const SessionBundle& sessions,
                     uint16_t keylength,
                     std::optional<uint32_t> exponent = {});

      // static std::unique_ptr<RSA_PrivateKey> create_transient(const std::shared_ptr<Context>& ctx,
      //                                                         std::span<const uint8_t> auth_value,
      //                                                         const SessionBundle& sessions);

      // static std::unique_ptr<RSA_PrivateKey> create_persistent(const std::shared_ptr<Context>& ctx,
      //                                                          uint32_t persistent_object_handle,
      //                                                          std::span<const uint8_t> auth_value,
      //                                                          const SessionBundle& sessions);

      // Somewhere:
      // evict_object(m_handle, sessions) // Evicts from persistent storage
      // make_persistent(m_handle, persistent_object_handle, sessions)

   public:
      std::unique_ptr<Public_Key> public_key() const override {
         return std::make_unique<Botan::RSA_PublicKey>(algorithm_identifier(), public_key_bits());
      }

      secure_vector<uint8_t> private_key_bits() const override;

      const Object& handles() const { return m_handle; }

      std::unique_ptr<PK_Ops::Signature> create_signature_op(RandomNumberGenerator& rng,
                                                             std::string_view params,
                                                             std::string_view provider) const override;

      struct CreationData {
            Object handle;
            std::vector<uint8_t> private_blob = {};
            Botan::BigInt n;
            Botan::BigInt e;
      };

   protected:
      RSA_PrivateKey(Object obj, SessionBundle sessions);
      RSA_PrivateKey(CreationData data, SessionBundle sessions);

   private:
      Object m_handle;
      SessionBundle m_sessions;

      std::vector<uint8_t> m_private_blob;
};

BOTAN_DIAGNOSTIC_POP

}  // namespace Botan::TPM2

#endif
