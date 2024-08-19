/*
* TPM 2.0 Key Wrappers' Base Class
* (C) 2024 Jack Lloyd
* (C) 2024 René Meusel, Amos Treiber - Rohde & Schwarz Cybersecurity GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/
#ifndef BOTAN_TPM2_ASYM_KEYS_H_
#define BOTAN_TPM2_ASYM_KEYS_H_

#include <botan/pk_keys.h>
#include <botan/tpm2_context.h>
#include <botan/tpm2_object.h>
#include <botan/tpm2_session.h>

struct TPM2B_SENSITIVE_CREATE;
struct TPMT_PUBLIC;

namespace Botan::TPM2 {

class BOTAN_PUBLIC_API(3, 6) PublicKey : public virtual Botan::Public_Key {
   public:
      static std::unique_ptr<PublicKey> load_persistent(const std::shared_ptr<Context>& ctx,
                                                        uint32_t persistent_object_handle,
                                                        const SessionBundle& sessions = {});

      static std::unique_ptr<PublicKey> load_transient(const std::shared_ptr<Context>& ctx,
                                                       std::span<const uint8_t> public_blob,
                                                       const SessionBundle& sessions);

   public:
      std::unique_ptr<Private_Key> generate_another(RandomNumberGenerator&) const override {
         throw Not_Implemented("Cannot generate a new TPM-based keypair from this asymmetric key");
      }

      /**
       * @returns a TPM2-specific marshalled representation of the public key
       */
      std::vector<uint8_t> raw_public_key_bits() const override;

      const Object& handles() const { return m_handle; }

      const SessionBundle& sessions() const { return m_sessions; }

   protected:
      PublicKey(Object object, SessionBundle sessions) : m_handle(std::move(object)), m_sessions(std::move(sessions)) {}

   private:
      Object m_handle;
      SessionBundle m_sessions;
};

BOTAN_DIAGNOSTIC_PUSH
BOTAN_DIAGNOSTIC_IGNORE_INHERITED_VIA_DOMINANCE

class BOTAN_PUBLIC_API(3, 6) PrivateKey : public virtual Private_Key {
   public:
      static std::unique_ptr<PrivateKey> load_persistent(const std::shared_ptr<Context>& ctx,
                                                         uint32_t persistent_object_handle,
                                                         std::span<const uint8_t> auth_value,
                                                         const SessionBundle& sessions);

      static std::unique_ptr<PrivateKey> load_transient(const std::shared_ptr<Context>& ctx,
                                                        std::span<const uint8_t> auth_value,
                                                        const TPM2::PrivateKey& parent,
                                                        std::span<const uint8_t> public_blob,
                                                        std::span<const uint8_t> private_blob,
                                                        const SessionBundle& sessions);

      /**
       * This is a wrapper around Esys_CreateLoaded creating a transient key
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
      static std::unique_ptr<PrivateKey> create_transient_from_template(const std::shared_ptr<Context>& ctx,
                                                                        const SessionBundle& sessions,
                                                                        const TPM2::PrivateKey& parent,
                                                                        const TPMT_PUBLIC* key_template,
                                                                        const TPM2B_SENSITIVE_CREATE* sensitive_data);

   public:
      /// @throws Not_Implemented keys hosted in a TPM2 cannot be exported
      secure_vector<uint8_t> private_key_bits() const override {
         throw Not_Implemented("cannot export private key bits from a TPM2 key, maybe use raw_private_key_bits()?");
      }

      /**
       * @returns the encrypted private key blob, if the key is transient
       * @throws Invalid_State if the key is persistent
       */
      secure_vector<uint8_t> raw_private_key_bits() const override;

      /**
       * @returns a TPM2-specific marshalled representation of the public key
       */
      std::vector<uint8_t> raw_public_key_bits() const override;

      Object& handles() { return m_handle; }

      const Object& handles() const { return m_handle; }

      const SessionBundle& sessions() const { return m_sessions; }

   protected:
      PrivateKey(Object handle, SessionBundle sessions, std::span<const uint8_t> private_blob = {}) :
            m_handle(std::move(handle)),
            m_sessions(std::move(sessions)),
            m_private_blob(private_blob.begin(), private_blob.end()) {}

   private:
      Object m_handle;
      SessionBundle m_sessions;

      /// Transient keys can be exported as an encrypted private blob that is
      /// readable by the TPM that created it.
      std::vector<uint8_t> m_private_blob;
};

BOTAN_DIAGNOSTIC_POP

}  // namespace Botan::TPM2

#endif
