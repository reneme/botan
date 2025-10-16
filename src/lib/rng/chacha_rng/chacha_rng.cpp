/*
* ChaCha_RNG
* (C) 2017 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/chacha_rng.h>

#include <botan/assert.h>

namespace Botan {

ChaCha_RNG::ChaCha_RNG(bool fast_key_erasure) :
      m_hmac(MessageAuthenticationCode::create_or_throw(m_hmac_algo)),
      m_chacha(StreamCipher::create_or_throw(m_stream_cipher_algo)),
      m_fast_key_erasure(fast_key_erasure),
      m_chacha_keylen(m_chacha->key_spec().maximum_keylength()) {
   clear();
}

ChaCha_RNG::ChaCha_RNG(std::span<const uint8_t> seed, bool fast_key_erasure) : ChaCha_RNG(fast_key_erasure) {
   add_entropy(seed);
}

ChaCha_RNG::ChaCha_RNG(RandomNumberGenerator& underlying_rng, size_t reseed_interval, bool fast_key_erasure) :
      Stateful_RNG(underlying_rng, reseed_interval),
      m_hmac(MessageAuthenticationCode::create_or_throw(m_hmac_algo)),
      m_chacha(StreamCipher::create_or_throw(m_stream_cipher_algo)),
      m_fast_key_erasure(fast_key_erasure),
      m_chacha_keylen(m_chacha->key_spec().maximum_keylength()) {
   clear();
}

ChaCha_RNG::ChaCha_RNG(RandomNumberGenerator& underlying_rng,
                       Entropy_Sources& entropy_sources,
                       size_t reseed_interval,
                       bool fast_key_erasure) :
      Stateful_RNG(underlying_rng, entropy_sources, reseed_interval),
      m_hmac(MessageAuthenticationCode::create_or_throw(m_hmac_algo)),
      m_chacha(StreamCipher::create_or_throw(m_stream_cipher_algo)),
      m_fast_key_erasure(fast_key_erasure),
      m_chacha_keylen(m_chacha->key_spec().maximum_keylength()) {
   clear();
}

ChaCha_RNG::ChaCha_RNG(Entropy_Sources& entropy_sources, size_t reseed_interval, bool fast_key_erasure) :
      Stateful_RNG(entropy_sources, reseed_interval),
      m_hmac(MessageAuthenticationCode::create_or_throw(m_hmac_algo)),
      m_chacha(StreamCipher::create_or_throw(m_stream_cipher_algo)),
      m_fast_key_erasure(fast_key_erasure),
      m_chacha_keylen(m_chacha->key_spec().maximum_keylength()) {
   clear();
}

void ChaCha_RNG::clear_state() {
   m_hmac->set_key(std::vector<uint8_t>(m_hmac->output_length(), 0x00));
   const auto chacha_key = m_hmac->final();
   m_chacha->set_key(chacha_key.data(), m_chacha_keylen);
   m_chacha->set_iv(chacha_key.data() + m_chacha_keylen, m_chacha_iv_len);
}

void ChaCha_RNG::generate_output(std::span<uint8_t> output, std::span<const uint8_t> input) {
   BOTAN_ASSERT_NOMSG(!output.empty());

   if(!input.empty()) {
      update(input);
   }

   m_chacha->write_keystream(output);

   // optionally overwrite key after each output operation for backtracking resistance
   if(m_fast_key_erasure) {
      const auto chacha_key = m_chacha->keystream_bytes(m_chacha_keylen + m_chacha_iv_len);
      m_chacha->set_key(chacha_key.data(), m_chacha_keylen);
      m_chacha->set_iv(chacha_key.data() + m_chacha_keylen, m_chacha_iv_len);
   }
}

void ChaCha_RNG::update(std::span<const uint8_t> input) {
   m_hmac->update(input);
   const auto chacha_key = m_hmac->final();
   m_chacha->set_key(chacha_key.data(), m_chacha_keylen);
   m_chacha->set_iv(chacha_key.data() + m_chacha_keylen, m_chacha_iv_len);
   const auto mac_key = m_chacha->keystream_bytes(m_hmac->output_length());
   m_hmac->set_key(mac_key);
}

size_t ChaCha_RNG::security_level() const {
   return 256;
}

}  // namespace Botan
