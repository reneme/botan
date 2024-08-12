/*
* TPM 2 interface
* (C) 2024 Jack Lloyd
* (C) 2024 René Meusel, Amos Treiber - Rohde & Schwarz Cybersecurity GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_TPM2_CONTEXT_H_
#define BOTAN_TPM2_CONTEXT_H_

#include <botan/exceptn.h>
#include <botan/rng.h>

#include <memory>
#include <optional>
#include <vector>

namespace Botan::TPM2 {

struct CryptoCallbackState;

class RSA_PrivateKey;  // TODO: remove, once a suitable TPM2-key base class is available
class SessionBundle;

class BOTAN_PUBLIC_API(3, 6) Context final : public std::enable_shared_from_this<Context> {
   public:
      /**
       * @param tcti_nameconf  this is passed to Tss2_TctiLdr_Initialize verbatim
       */
      static std::shared_ptr<Context> create(const std::string& tcti_nameconf);

      /**
       * @param tcti  if set this is passed to Tss2_TctiLdr_Initialize_Ex verbatim
       *              otherwise a nullptr is passed.
       * @param conf  if set this is passed to Tss2_TctiLdr_Initialize_Ex verbatim
       *              otherwise a nullptr is passed.
       */
      static std::shared_ptr<Context> create(std::optional<std::string> tcti = {},
                                             std::optional<std::string> conf = {});

      Context(const Context&) = delete;
      Context(Context&& ctx) noexcept = default;
      ~Context();

      Context& operator=(const Context&) = delete;
      Context& operator=(Context&& ctx) noexcept = default;

      /**
       * Overrides the TSS2's crypto callbacks with Botan's functionality.
       *
       * This replaces all cryptographic functionality required for the
       * communication with the TPM by botan's implementations. The TSS2
       * would otherwise use OpenSSL or mbedTLS.
       *
       * Note that the provided @p rng should not be dependent on the TPM.
       *
       * @param rng  the RNG to use for the crypto operations
       * @throws Not_Implemented if the TPM2-TSS does not support crypto callbacks
       * @sa supports_botan_crypto_backend()
       */
      void use_botan_crypto_backend(const std::shared_ptr<Botan::RandomNumberGenerator>& rng);

      /**
       * Checks if the TSS2 supports registering Botan's crypto backend at runtime.
       * Older versions of the TSS2 do not support this feature ( 4.0.0), also
       * Botan may be compiled without support for TSS' crypto backend.
       * @return true if the TSS2 supports Botan's crypto backend
       */
      static bool supports_botan_crypto_backend() noexcept;

      /// @return an ESYS_CONTEXT* for use in other TPM2 functions.
      void* inner_context_object();

      /// @return the Vendor of the TPM2
      std::string vendor() const;

      /// @returns the Manufacturer of the TPM2
      std::string manufacturer() const;

      /// @returns the maximum number of random bytes to be requested at once
      size_t max_random_bytes_per_request() const;

      std::vector<uint32_t> persistent_handles() const;

      /// @return true if @p persistent_handle is in the list of persistent handles
      bool in_persistent_handles(uint32_t persistent_handle) const;

      /// Makes @p key persistent at location @p persistent_handle
      void make_key_persistent(RSA_PrivateKey& key, uint32_t persistent_handle, const SessionBundle& sessions);

      /// Evicts the persistent key @p key
      void evict_persistent_key(RSA_PrivateKey& key, const SessionBundle& sessions);

      // TODO: This should return a TPM2::Private_Key base class of some sort
      // TODO: Currently this assumes that the SRK is a persistent object,
      //       this assumption may not hold forever.
      std::unique_ptr<RSA_PrivateKey> storage_root_key(std::span<const uint8_t> auth_value,
                                                       const SessionBundle& sessions);

   private:
      Context(const char* tcti_nameconf);
      Context(const char* tcti_name, const char* tcti_conf);

#if defined(BOTAN_HAS_TPM2_CRYPTO_BACKEND)
      friend void enable_crypto_callbacks(const std::shared_ptr<Context>&);
      CryptoCallbackState& crypto_callback_state();
#endif

   private:
      struct Impl;  // PImpl to avoid TPM2-TSS includes in this header
      std::unique_ptr<Impl> m_impl;
};

}  // namespace Botan::TPM2

#endif
