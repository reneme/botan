/*
* TPM 2 Keys
* (C) 2024 Jack Lloyd
* (C) 2024 René Meusel, Amos Treiber - Rohde & Schwarz Cybersecurity GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/
#ifndef BOTAN_TPM2_KEYS_H_
#define BOTAN_TPM2_KEYS_H_

#include <botan/pk_keys.h>
#include <botan/tpm2.h>

#include <utility>

namespace Botan::TPM2 {

class BOTAN_PUBLIC_API(3, 6) Key final : public Private_Key {
      //TODO: Constructors

   public:
      /** If the key does not exist, it will be created under the given id and the handle 0x81000000 + id.
      * If the key already exists, it will be loaded from the TPM.
      * @param ctx  The TPM2 context
      * @param key_persistent_id  The persistent id of the key
      * @param auth_value  The authorization value for the key
      * TODO: Maybe create these only via the context?
      */
      Key(std::shared_ptr<Context> ctx, uint32_t key_persistent_id, std::span<const uint8_t> auth_value);

      ~Key() override;

      uint32_t handle() const { return m_persistent_key_handle; }

      uint32_t transient_handle() const { return m_transient_key_handle; }

      std::string algo_name() const override { return "RSA"; }  // TODO: Other types

      std::unique_ptr<Public_Key> public_key() const override;

      std::unique_ptr<Private_Key> generate_another(RandomNumberGenerator&) const override {
         throw Not_Implemented("Cannot generate a new TPM-based keypair from this asymmetric key");
      }

      size_t estimated_strength() const override;

      size_t key_length() const override;

      AlgorithmIdentifier algorithm_identifier() const override;

      std::vector<uint8_t> public_key_bits() const override;

      std::vector<uint8_t> raw_public_key_bits() const override;

      secure_vector<uint8_t> private_key_bits() const override;

      bool check_key(RandomNumberGenerator& rng, bool) const override;

      //TODO: Other types
      bool supports_operation(PublicKeyOperation op) const override { return (op == PublicKeyOperation::Signature); }

      std::unique_ptr<PK_Ops::Signature> create_signature_op(RandomNumberGenerator& rng,
                                                             std::string_view params,
                                                             std::string_view provider) const override;

      // TODO: Key Deletion

   private:
      void create_new(uint32_t key_handle, const std::string& auth_val);

   private:
      std::shared_ptr<Context> m_ctx;

      uint32_t m_persistent_key_handle;          // Represents a TPM2_HANDLE
      uint32_t m_transient_key_handle = 0xfffU;  // Represents a ESYS_TR initialized to ESYS_TR_NONE

      bool m_is_persistent = false;
};

}  // namespace Botan::TPM2

#endif
