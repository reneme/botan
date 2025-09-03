/*
* SHA-3
* (C) 2010,2016 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/sha3.h>

#include <botan/exceptn.h>
#include <botan/internal/fmt.h>
#include <botan/internal/keccak_perm.h>
#include <botan/internal/loadstor.h>

namespace Botan {

namespace {

constexpr Keccak_Permutation select_permutation(size_t output_bits) {
   constexpr Keccak_Permutation::Config sha3_config = {.custom_padding = 0x02, .custom_padding_bit_len = 2};
   switch(output_bits) {
      case 224:
         return Keccak_Permutation({.bit_rate = 448, .initial_state = {}}, sha3_config);
      case 256:
         return Keccak_Permutation({.bit_rate = 512, .initial_state = {}}, sha3_config);
      case 384:
         return Keccak_Permutation({.bit_rate = 768, .initial_state = {}}, sha3_config);
      case 512:
         return Keccak_Permutation({.bit_rate = 1024, .initial_state = {}}, sha3_config);
      default:
         throw Invalid_Argument(fmt("SHA_3: Invalid output length {}", output_bits));
   }
}

}  // namespace

SHA_3::SHA_3(size_t output_bits) : m_keccak(select_permutation(output_bits)), m_output_length(output_bits / 8) {
   // We only support the parameters for SHA-3 in this constructor

   if(output_bits != 224 && output_bits != 256 && output_bits != 384 && output_bits != 512) {
      throw Invalid_Argument(fmt("SHA_3: Invalid output length {}", output_bits));
   }
}

std::string SHA_3::name() const {
   return fmt("SHA-3({})", m_output_length * 8);
}

std::string SHA_3::provider() const {
   return m_keccak.provider();
}

std::unique_ptr<HashFunction> SHA_3::copy_state() const {
   return std::make_unique<SHA_3>(*this);
}

std::unique_ptr<HashFunction> SHA_3::new_object() const {
   return std::make_unique<SHA_3>(m_output_length * 8);
}

void SHA_3::clear() {
   m_keccak = select_permutation(m_output_length * 8);
}

void SHA_3::add_data(std::span<const uint8_t> input) {
   m_keccak.absorb(input);
}

void SHA_3::final_result(std::span<uint8_t> output) {
   m_keccak.finish();
   m_keccak.squeeze(output);
   clear();
}

}  // namespace Botan
