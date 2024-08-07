/*
* TPM 2 TSS crypto callbacks backend
* (C) 2024 Jack Lloyd
* (C) 2024 René Meusel, Amos Treiber - Rohde & Schwarz Cybersecurity GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/tpm2_crypto_backend.h>

#include <botan/internal/fmt.h>
#include <botan/internal/tpm2_algo_mappings.h>
#include <botan/internal/tpm2_util.h>

#include <botan/cipher_mode.h>
#include <botan/hash.h>
#include <botan/mac.h>
#include <botan/tpm2_context.h>

#include <tss2/tss2_esys.h>

#include <variant>

#if defined(BOTAN_TSS2_SUPPORTS_CRYPTO_CALLBACKS)

namespace {

/// Holds the hash state between update callback invocations
using DigestObject =
   std::variant<std::unique_ptr<Botan::HashFunction>, std::unique_ptr<Botan::MessageAuthenticationCode>>;

}  // namespace

extern "C" {

/**
 * Some ESYS crypto callbacks require to hold state between calls.
 * This struct is forward-declared in tss2_esys.h and we're implementing it here.
 */
typedef struct ESYS_CRYPTO_CONTEXT_BLOB {
      DigestObject ctx;
} DigestCallbackState;

}  // extern "C"

namespace {

/// Safely converts the @p blob to a Botan crypto object of type @p T.
template <typename T>
   requires std::constructible_from<DigestObject, std::unique_ptr<T>>
[[nodiscard]] std::optional<std::reference_wrapper<T>> get(DigestCallbackState* blob) noexcept {
   if(!blob) {
      return std::nullopt;
   }

   if(!std::holds_alternative<std::unique_ptr<T>>(blob->ctx)) {
      return std::nullopt;
   }

   return {std::ref(*std::get<std::unique_ptr<T>>(blob->ctx))};
}

/// Safely converts the @p userdata to the Botan crypto context object.
[[nodiscard]] std::optional<std::reference_wrapper<Botan::TPM2::CryptoCallbackState>> get(void* userdata) noexcept {
   if(!userdata) {
      return std::nullopt;
   }

   auto ccs = reinterpret_cast<Botan::TPM2::CryptoCallbackState*>(userdata);
   if(!ccs) {
      return std::nullopt;
   }

   return *ccs;
}

/**
 * Wraps the Botan-specific implementations of the TSS crypto callbacks into a
 * try-catch block and converts encountered exceptions to TSS2_RC error codes as
 * needed.
 */
template <std::invocable<> F>
   requires std::same_as<std::invoke_result_t<F>, TSS2_RC>
[[nodiscard]] TSS2_RC thunk(F&& f) noexcept {
   try {
      return f();
   } catch(const Botan::Invalid_Argument&) {
      return TSS2_ESYS_RC_BAD_VALUE;
   } catch(const Botan::Invalid_State&) {
      return TSS2_ESYS_RC_BAD_SEQUENCE;
   } catch(const Botan::Lookup_Error&) {
      return TSS2_ESYS_RC_NOT_IMPLEMENTED;
   } catch(const Botan::Invalid_Authentication_Tag&) {
      return TSS2_ESYS_RC_MALFORMED_RESPONSE;
   } catch(const Botan::Exception&) {
      return TSS2_ESYS_RC_GENERAL_FAILURE;
   } catch(...) {
      return TSS2_ESYS_RC_GENERAL_FAILURE;
   }
}

/**
 * Encrypts or decrypts @p data using the symmetric cipher specified.
 * The bytes in @p data are encrypted/decrypted in-place.
 */
[[nodiscard]] TSS2_RC symmetric_algo(Botan::Cipher_Dir direction,
                                     TPM2_ALG_ID tpm_sym_alg,
                                     TPMI_AES_KEY_BITS key_bits,
                                     TPM2_ALG_ID tpm_mode,
                                     const uint8_t* key,
                                     const uint8_t* iv,
                                     std::span<uint8_t> data) noexcept {
   return thunk([&] {
      if(!key) {
         return (direction == Botan::Cipher_Dir::Encryption) ? TSS2_ESYS_RC_NO_ENCRYPT_PARAM
                                                             : TSS2_ESYS_RC_NO_DECRYPT_PARAM;
      }

      const auto cipher_name = Botan::TPM2::cipher_mode_tss2_to_botan(tpm_sym_alg, key_bits, tpm_mode);
      if(!cipher_name) {
         return TSS2_ESYS_RC_NOT_SUPPORTED;
      }

      auto cipher = Botan::Cipher_Mode::create(cipher_name.value(), direction);
      if(!cipher) {
         return TSS2_ESYS_RC_NOT_IMPLEMENTED;
      }

      // AEADs aren't supported by the crypto callback API, as there's
      // no way to append the authentication tag to the ciphertext.
      if(cipher->authenticated()) {
         return TSS2_ESYS_RC_INSUFFICIENT_BUFFER;
      }

      const size_t keylength = static_cast<size_t>(key_bits) / 8;
      if(!cipher->valid_keylength(keylength)) {
         return TSS2_ESYS_RC_BAD_VALUE;
      }

      const auto s_key = std::span{key, keylength};
      const auto s_iv = [&]() -> std::span<const uint8_t> {
         if(iv) {
            return {iv, cipher->default_nonce_length()};
         } else {
            return {};
         }
      }();

      cipher->set_key(s_key);
      cipher->start(s_iv);
      cipher->process(data);
      return TSS2_RC_SUCCESS;
   });
}

}  // namespace

extern "C" {

/** Encryption of a buffer using a public (RSA) key.
 *
 * Encrypting a buffer using a public key is used for example during
 * Esys_StartAuthSession in order to encrypt the salt value.
 * @param[in] pub_tpm_key The key to be used for encryption.
 * @param[in] in_size The size of the buffer to be encrypted.
 * @param[in] in_buffer The data buffer to be encrypted.
 * @param[in] max_out_size The maximum size for the output encrypted buffer.
 * @param[out] out_buffer The encrypted buffer.
 * @param[out] out_size The size of the encrypted output.
 * @param[in] label The label used in the encryption scheme.
 * @param[in,out] userdata information.
 * @retval TSS2_RC_SUCCESS on success
 * @retval USER_DEFINED user defined errors on failure.
 */
TSS2_RC rsa_pk_encrypt(TPM2B_PUBLIC* pub_tpm_key,
                       size_t in_size,
                       BYTE* in_buffer,
                       size_t max_out_size,
                       BYTE* out_buffer,
                       size_t* out_size,
                       const char* label,
                       void* userdata) {
   BOTAN_UNUSED(pub_tpm_key, in_size, in_buffer, max_out_size, out_buffer, out_size, label, userdata);
   // This is currently not required for the exposed functionality.
   // TODO: Implement this function if required.
   return TSS2_ESYS_RC_NOT_IMPLEMENTED;
}

/** Provide the context for the computation of a hash digest.
 *
 * The context will be created and initialized according to the hash function.
 * @param[out] context The created context (callee-allocated).
 * @param[in] hash_alg The hash algorithm for the creation of the context.
 * @param[in,out] userdata information.
 * @retval TSS2_RC_SUCCESS on success.
 * @retval USER_DEFINED user defined errors on failure.
 */
TSS2_RC hash_start(ESYS_CRYPTO_CONTEXT_BLOB** context, TPM2_ALG_ID hash_alg, void* userdata) {
   BOTAN_UNUSED(userdata);
   return thunk([&] {
      const auto hash_name = Botan::TPM2::hash_algo_tss2_to_botan(hash_alg);
      if(!hash_name) {
         return TSS2_ESYS_RC_NOT_SUPPORTED;
      }

      auto hash = Botan::HashFunction::create(hash_name.value());
      if(!hash) {
         return TSS2_ESYS_RC_NOT_IMPLEMENTED;
      }

      *context = new DigestCallbackState{std::move(hash)};
      return TSS2_RC_SUCCESS;
   });
}

/** Update the digest value of a digest object from a byte buffer.
 *
 * The context of a digest object will be updated according to the hash
 * algorithm of the context. <
 * @param[in,out] context The context of the digest object which will be updated.
 * @param[in] buffer The data for the update.
 * @param[in] size The size of the data buffer.
 * @param[in,out] userdata information.
 * @retval TSS2_RC_SUCCESS on success.
 * @retval USER_DEFINED user defined errors on failure.
 */
TSS2_RC hash_update(ESYS_CRYPTO_CONTEXT_BLOB* context, const uint8_t* buffer, size_t size, void* userdata) {
   BOTAN_UNUSED(userdata);
   return thunk([&] {
      const auto hash = get<Botan::HashFunction>(context);
      if(!hash) {
         return TSS2_ESYS_RC_BAD_REFERENCE;
      }

      hash->get().update(std::span{buffer, size});
      return TSS2_RC_SUCCESS;
   });
}

/** Get the digest value of a digest object and close the context.
 *
 * The digest value will written to a passed buffer and the resources of the
 * digest object are released.
 * @param[in,out] context The context of the digest object to be released
 * @param[out] buffer The buffer for the digest value (caller-allocated).
 * @param[out] size The size of the digest.
 * @param[in,out] userdata information.
 * @retval TSS2_RC_SUCCESS on success.
 * @retval USER_DEFINED user defined errors on failure.
 */
TSS2_RC hash_finish(ESYS_CRYPTO_CONTEXT_BLOB** context, uint8_t* buffer, size_t* size, void* userdata) {
   BOTAN_UNUSED(userdata);
   return thunk([&] {
      auto hash = get<Botan::HashFunction>(*context);
      if(!hash) {
         return TSS2_ESYS_RC_BAD_REFERENCE;
      }

      *size = hash->get().output_length();
      hash->get().final(std::span{buffer, *size});

      delete *context;
      *context = nullptr;
      return TSS2_RC_SUCCESS;
   });
}

/** Release the resources of a digest object.
 *
 * The assigned resources will be released and the context will be set to NULL.
 * @param[in,out] context The context of the digest object.
 * @param[in,out] userdata information.
 */
void hash_abort(ESYS_CRYPTO_CONTEXT_BLOB** context, void* userdata) {
   BOTAN_UNUSED(userdata);
   delete *context;
   *context = nullptr;
}

/** Provide the context an HMAC digest object from a byte buffer key.
 *
 * The context will be created and initialized according to the hash function
 * and the used HMAC key.
 * @param[out] context The created context (callee-allocated).
 * @param[in] hash_alg The hash algorithm for the HMAC computation.
 * @param[in] key The byte buffer of the HMAC key.
 * @param[in] size The size of the HMAC key.
 * @param[in,out] userdata information.
 * @retval TSS2_RC_SUCCESS on success.
 * @retval USER_DEFINED user defined errors on failure.
 */
TSS2_RC hmac_start(
   ESYS_CRYPTO_CONTEXT_BLOB** context, TPM2_ALG_ID hash_alg, const uint8_t* key, size_t size, void* userdata) {
   BOTAN_UNUSED(userdata);
   return thunk([&] {
      const auto hash_name = Botan::TPM2::hash_algo_tss2_to_botan(hash_alg);
      if(!hash_name) {
         return TSS2_ESYS_RC_NOT_SUPPORTED;
      }

      auto hmac = Botan::MessageAuthenticationCode::create(Botan::fmt("HMAC({})", hash_name.value()));
      if(!hmac) {
         return TSS2_ESYS_RC_NOT_IMPLEMENTED;
      }

      hmac->set_key(std::span{key, size});

      *context = new DigestCallbackState{std::move(hmac)};
      return TSS2_RC_SUCCESS;
   });
}

/** Update and HMAC digest value from a byte buffer.
 *
 * The context of a digest object will be updated according to the hash
 * algorithm and the key of the context.
 * @param[in,out] context The context of the digest object which will be updated.
 * @param[in] buffer The data for the update.
 * @param[in] size The size of the data buffer.
 * @param[in,out] userdata information.
 * @retval TSS2_RC_SUCCESS on success.
 * @retval USER_DEFINED user defined errors on failure.
 */
TSS2_RC hmac_update(ESYS_CRYPTO_CONTEXT_BLOB* context, const uint8_t* buffer, size_t size, void* userdata) {
   BOTAN_UNUSED(userdata);
   return thunk([&] {
      auto hmac = get<Botan::MessageAuthenticationCode>(context);
      if(!hmac) {
         return TSS2_ESYS_RC_BAD_REFERENCE;
      }

      hmac->get().update(std::span{buffer, size});
      return TSS2_RC_SUCCESS;
   });
}

/** Write the HMAC digest value to a byte buffer and close the context.
 *
 * The digest value will written to a passed buffer and the resources of the
 * HMAC object are released.
 * @param[in,out] context The context of the HMAC object.
 * @param[out] buffer The buffer for the digest value (caller-allocated).
 * @param[out] size The size of the digest.
 * @param[in,out] userdata information.
 * @retval TSS2_RC_SUCCESS on success.
 * @retval USER_DEFINED user defined errors on failure.
 */
TSS2_RC hmac_finish(ESYS_CRYPTO_CONTEXT_BLOB** context, uint8_t* buffer, size_t* size, void* userdata) {
   BOTAN_UNUSED(userdata);
   return thunk([&] {
      auto hmac = get<Botan::MessageAuthenticationCode>(*context);
      if(!hmac) {
         return TSS2_ESYS_RC_BAD_REFERENCE;
      }

      *size = hmac->get().output_length();
      hmac->get().final(std::span{buffer, *size});

      delete *context;
      *context = nullptr;
      return TSS2_RC_SUCCESS;
   });
}

/** Release the resources of an HMAC object.
 *
 * The assigned resources will be released and the context will be set to NULL.
 * @param[in,out] context The context of the HMAC object.
 * @param[in,out] userdata information.
 */
void hmac_abort(ESYS_CRYPTO_CONTEXT_BLOB** context, void* userdata) {
   BOTAN_UNUSED(userdata);
   delete *context;
   *context = nullptr;
}

/** Compute random TPM2B data.
 *
 * The random data will be generated and written to a passed TPM2B structure.
 * @param[out] nonce The TPM2B structure for the random data (caller-allocated).
 * @param[in] num_bytes The number of bytes to be generated.
 * @param[in,out] userdata information.
 * @retval TSS2_RC_SUCCESS on success.
 * @retval USER_DEFINED user defined errors on failure.
 * @note: the TPM should not be used to obtain the random data
 */
TSS2_RC get_random2b(TPM2B_NONCE* nonce, size_t num_bytes, void* userdata) {
   return thunk([&] {
      auto ccs = get(userdata);
      if(!ccs) {
         return TSS2_ESYS_RC_BAD_REFERENCE;
      }

      nonce->size = num_bytes;
      ccs->get().rng->randomize(Botan::TPM2::as_span(*nonce));
      return TSS2_RC_SUCCESS;
   });
}

/** Computation of an ephemeral ECC key and shared secret Z.
 *
 * According to the description in TPM spec part 1 C 6.1 a shared secret
 * between application and TPM is computed (ECDH). An ephemeral ECC key and a
 * TPM key are used for the ECDH key exchange.
 * @param[in] key The key to be used for ECDH key exchange.
 * @param[in] max_out_size the max size for the output of the public key of the
 *            computed ephemeral key.
 * @param[out] Z The computed shared secret.
 * @param[out] Q The public part of the ephemeral key in TPM format.
 * @param[out] out_buffer The public part of the ephemeral key will be marshaled
 *             to this buffer.
 * @param[out] out_size The size of the marshaled output.
 * @param[in,out] userdata information.
 * @retval TSS2_RC_SUCCESS on success
 * @retval USER_DEFINED user defined errors on failure.
 */
TSS2_RC get_ecdh_point(TPM2B_PUBLIC* key,
                       size_t max_out_size,
                       TPM2B_ECC_PARAMETER* Z,
                       TPMS_ECC_POINT* Q,
                       BYTE* out_buffer,
                       size_t* out_size,
                       void* userdata) {
   BOTAN_UNUSED(key, max_out_size, Z, Q, out_buffer, out_size, userdata);
   // This is currently not required for the exposed functionality.
   // TODO: Implement this function if required.
   return TSS2_ESYS_RC_NOT_IMPLEMENTED;
}

/** Encrypt data with AES.
 *
 * @param[in] key key used for AES.
 * @param[in] tpm_sym_alg AES type in TSS2 notation (must be TPM2_ALG_AES).
 * @param[in] key_bits Key size in bits.
 * @param[in] tpm_mode Block cipher mode of opertion in TSS2 notation (CFB).
 *            For parameter encryption only CFB can be used.
 * @param[in,out] buffer Data to be encrypted. The encrypted date will be stored
 *                in this buffer.
 * @param[in] buffer_size size of data to be encrypted.
 * @param[in] iv The initialization vector.
 * @param[in,out] userdata information.
 * @retval TSS2_RC_SUCCESS on success
 * @retval USER_DEFINED user defined errors on failure.
 */
TSS2_RC aes_encrypt(uint8_t* key,
                    TPM2_ALG_ID tpm_sym_alg,
                    TPMI_AES_KEY_BITS key_bits,
                    TPM2_ALG_ID tpm_mode,
                    uint8_t* buffer,
                    size_t buffer_size,
                    uint8_t* iv,
                    void* userdata) {
   BOTAN_UNUSED(userdata);
   if(tpm_sym_alg != TPM2_ALG_AES) {
      return TSS2_ESYS_RC_BAD_VALUE;
   }

   return symmetric_algo(
      Botan::Cipher_Dir::Encryption, tpm_sym_alg, key_bits, tpm_mode, key, iv, std::span{buffer, buffer_size});
}

/** Decrypt data with AES.
 *
 * @param[in] key key used for AES.
 * @param[in] tpm_sym_alg AES type in TSS2 notation (must be TPM2_ALG_AES).
 * @param[in] key_bits Key size in bits.
 * @param[in] tpm_mode Block cipher mode of opertion in TSS2 notation (CFB).
 *            For parameter encryption only CFB can be used.
 * @param[in,out] buffer Data to be decrypted. The decrypted date will be stored
 *                in this buffer.
 * @param[in] buffer_size size of data to be encrypted.
 * @param[in] iv The initialization vector.
 * @param[in,out] userdata information.
 * @retval TSS2_RC_SUCCESS on success
 * @retval USER_DEFINED user defined errors on failure.
 */
TSS2_RC aes_decrypt(uint8_t* key,
                    TPM2_ALG_ID tpm_sym_alg,
                    TPMI_AES_KEY_BITS key_bits,
                    TPM2_ALG_ID tpm_mode,
                    uint8_t* buffer,
                    size_t buffer_size,
                    uint8_t* iv,
                    void* userdata) {
   BOTAN_UNUSED(userdata);
   if(tpm_sym_alg != TPM2_ALG_AES) {
      return TSS2_ESYS_RC_BAD_VALUE;
   }

   return symmetric_algo(
      Botan::Cipher_Dir::Decryption, tpm_sym_alg, key_bits, tpm_mode, key, iv, std::span{buffer, buffer_size});
}

   #if defined(BOTAN_TSS2_SUPPORTS_SM4_IN_CRYPTO_CALLBACKS)

/** Encrypt data with SM4.
 *
 * @param[in] key key used for SM4.
 * @param[in] tpm_sym_alg SM4 type in TSS2 notation (must be TPM2_ALG_SM4).
 * @param[in] key_bits Key size in bits.
 * @param[in] tpm_mode Block cipher mode of opertion in TSS2 notation (CFB).
 *            For parameter encryption only CFB can be used.
 * @param[in,out] buffer Data to be encrypted. The encrypted date will be stored
 *                in this buffer.
 * @param[in] buffer_size size of data to be encrypted.
 * @param[in] iv The initialization vector.
 * @param[in,out] userdata information.
 * @retval TSS2_RC_SUCCESS on success
 * @retval USER_DEFINED user defined errors on failure.
 */
TSS2_RC sm4_encrypt(uint8_t* key,
                    TPM2_ALG_ID tpm_sym_alg,
                    TPMI_SM4_KEY_BITS key_bits,
                    TPM2_ALG_ID tpm_mode,
                    uint8_t* buffer,
                    size_t buffer_size,
                    uint8_t* iv,
                    void* userdata) {
   BOTAN_UNUSED(userdata);
   if(tpm_sym_alg != TPM2_ALG_SM4) {
      return TSS2_ESYS_RC_BAD_VALUE;
   }

   return symmetric_algo(
      Botan::Cipher_Dir::Encryption, tpm_sym_alg, key_bits, tpm_mode, key, iv, std::span{buffer, buffer_size});
}

/** Decrypt data with SM4.
 *
 * @param[in] key key used for SM4.
 * @param[in] tpm_sym_alg SM4 type in TSS2 notation (must be TPM2_ALG_SM4).
 * @param[in] key_bits Key size in bits.
 * @param[in] tpm_mode Block cipher mode of opertion in TSS2 notation (CFB).
 *            For parameter encryption only CFB can be used.
 * @param[in,out] buffer Data to be decrypted. The decrypted date will be stored
 *                in this buffer.
 * @param[in] buffer_size size of data to be encrypted.
 * @param[in] iv The initialization vector.
 * @param[in,out] userdata information.
 * @retval TSS2_RC_SUCCESS on success
 * @retval USER_DEFINED user defined errors on failure.
 */
TSS2_RC sm4_decrypt(uint8_t* key,
                    TPM2_ALG_ID tpm_sym_alg,
                    TPMI_SM4_KEY_BITS key_bits,
                    TPM2_ALG_ID tpm_mode,
                    uint8_t* buffer,
                    size_t buffer_size,
                    uint8_t* iv,
                    void* userdata) {
   BOTAN_UNUSED(userdata);
   if(tpm_sym_alg != TPM2_ALG_SM4) {
      return TSS2_ESYS_RC_BAD_VALUE;
   }

   return symmetric_algo(
      Botan::Cipher_Dir::Decryption, tpm_sym_alg, key_bits, tpm_mode, key, iv, std::span{buffer, buffer_size});
}

   #endif /* TPM2_ALG_SM4 */

/** Initialize crypto backend.
 *
 * Initialize internal tables of crypto backend.
 *
 * @param[in,out] userdata Optional userdata pointer.
 *
 * @retval TSS2_RC_SUCCESS ong success.
 * @retval USER_DEFINED user defined errors on failure.
 */
TSS2_RC init(void* userdata) {
   // No dedicated initialization required. Just check if the userdata is valid.
   auto ccs = get(userdata);
   if(!ccs) {
      return TSS2_ESYS_RC_BAD_REFERENCE;
   }
   if(!ccs->get().rng) {
      return TSS2_ESYS_RC_BAD_SEQUENCE;
   }
   return TSS2_RC_SUCCESS;
}

}  // extern "C"

#endif /* BOTAN_TSS2_SUPPORTS_CRYPTO_CALLBACKS */

namespace Botan::TPM2 {

/**
 * Enable the Botan crypto callbacks for the given ESYS context.
 *
 * The callbacks may maintain two types of state:
 *
 *  * 'userdata' is a pointer to a CryptoCallbackState object that is passed
 *               to all callback functions. This provides access to a random
 *               number generator specified by the user.
 *               The lifetime of this object is bound to the TPM2::Context.
 *
 *  * 'context'  is a pointer to a DigestCallbackState object that contains
 *               either a HashFunction or a MessageAuthenticationCode object.
 *               This holds the hash state between update callback invocations.
 *               The lifetime of this object is bound to the digest callbacks,
 *               hence *_finish() and *_abort() will delete the object.
 *
 * The runtime crypto backend is available since TSS2 4.0.0 and later. Explicit
 * support for SM4 was added in TSS2 4.1.0.
 */
void enable_crypto_callbacks(const std::shared_ptr<Context>& ctx) {
#if defined(BOTAN_TSS2_SUPPORTS_CRYPTO_CALLBACKS)
   // clang-format off
   ESYS_CRYPTO_CALLBACKS callbacks{
      .rsa_pk_encrypt = &rsa_pk_encrypt,
      .hash_start     = &hash_start,
      .hash_update    = &hash_update,
      .hash_finish    = &hash_finish,
      .hash_abort     = &hash_abort,
      .hmac_start     = &hmac_start,
      .hmac_update    = &hmac_update,
      .hmac_finish    = &hmac_finish,
      .hmac_abort     = &hmac_abort,
      .get_random2b   = &get_random2b,
      .get_ecdh_point = &get_ecdh_point,
      .aes_encrypt    = &aes_encrypt,
      .aes_decrypt    = &aes_decrypt,
      .init           = &init,
      .userdata       = &ctx->crypto_callback_state(),
#if defined(BOTAN_TSS2_SUPPORTS_SM4_IN_CRYPTO_CALLBACKS)
      .sm4_encrypt    = &sm4_encrypt,
      .sm4_decrypt    = &sm4_decrypt,
#endif
   };
   // clang-format on

   check_rc("Esys_SetCryptoCallbacks", Esys_SetCryptoCallbacks(inner(ctx), &callbacks));
#else
   BOTAN_UNUSED(ctx);
   throw Not_Implemented(
      "This build of botan was compiled with a TSS2 version lower than 4.0.0, "
      "which dos not support custom runtime crypto backends");
#endif
}

}  // namespace Botan::TPM2
