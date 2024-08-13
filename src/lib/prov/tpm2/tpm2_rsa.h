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

struct TPM2B_SENSITIVE_CREATE;
struct TPMT_PUBLIC;

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
       * Create a transient RSA key with the given @p keylength and @p exponent,
       * under the given @p parent key, with the given @p auth_value.
       *
       * @param ctx The TPM context to use
       * @param sessions The session bundle to use in the creation of the key
       * @param auth_value The auth value to use for the key
       * @param parent The parent key to create the new key under
       * @param keylength The desired key length
       * @param exponent The desired exponent (default: 0x10001)
       */
      static std::unique_ptr<RSA_PrivateKey> create_transient(const std::shared_ptr<Context>& ctx,
                                                              const SessionBundle& sessions,
                                                              std::span<const uint8_t> auth_value,
                                                              const RSA_PrivateKey& parent,
                                                              uint16_t keylength,
                                                              std::optional<uint32_t> exponent = {});

      /**
       * This is a wrapper around Esys_CreateLoaded creating a transient RSA key
       * from a given @p key_template with @p sensitive_data. It gives maximal
       * flexibility to the caller to create a key with their own TSS2 template
       * configuration.
       *
       * Please use this if you know what you are doing, only! Most users should
       * use the more convenient create_transient() method.
       *
       * @param ctx The TPM context to use
       * @param sessions The session bundle to use in Esys_CreateLoaded().
       * @param parent The parent key to create the new key under.
       * @param key_template The template data to use for the key creation. It
       *                     will be passed to Tss2_MU_TPMT_PUBLIC_Marshal() and
       *                     Esys_CreateLoaded().
       * @param sensitive_data The sensitive data (e.g. with the desired auth
       *                       value) to use for the key creation.
       */
      static std::unique_ptr<RSA_PrivateKey> create_transient_from_template(
         const std::shared_ptr<Context>& ctx,
         const SessionBundle& sessions,
         const RSA_PrivateKey& parent,
         const TPMT_PUBLIC* key_template,
         const TPM2B_SENSITIVE_CREATE* sensitive_data);

   public:
      std::unique_ptr<Public_Key> public_key() const override {
         return std::make_unique<Botan::RSA_PublicKey>(algorithm_identifier(), public_key_bits());
      }

      secure_vector<uint8_t> private_key_bits() const override;

      Object& handles() { return m_handle; }

      const Object& handles() const { return m_handle; }

      std::unique_ptr<PK_Ops::Signature> create_signature_op(RandomNumberGenerator& rng,
                                                             std::string_view params,
                                                             std::string_view provider) const override;

   protected:
      RSA_PrivateKey(Object handle,
                     std::vector<uint8_t> private_blob,
                     Botan::RSA_PublicKey pubkey,
                     SessionBundle sessions) :
            Botan::RSA_PublicKey(std::move(pubkey)),
            m_handle(std::move(handle)),
            m_sessions(std::move(sessions)),
            m_private_blob(std::move(private_blob)) {}

      RSA_PrivateKey(Object handle, SessionBundle sessions);

   private:
      Object m_handle;
      SessionBundle m_sessions;

      std::vector<uint8_t> m_private_blob;
};

BOTAN_DIAGNOSTIC_POP

}  // namespace Botan::TPM2

#endif
