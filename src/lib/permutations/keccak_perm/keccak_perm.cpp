/*
* Keccak Permutation
* (C) 2010,2016 Jack Lloyd
* (C) 2023 Falko Strenzke
* (C) 2023 René Meusel - Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/keccak_perm.h>

#include <botan/exceptn.h>
#include <botan/internal/fmt.h>
#include <botan/internal/keccak_perm_round.h>
#include <botan/internal/loadstor.h>
#include <botan/internal/stl_util.h>

#if defined(BOTAN_HAS_CPUID)
   #include <botan/internal/cpuid.h>
#endif

namespace Botan {

std::string Keccak_Permutation::provider() const {
#if defined(BOTAN_HAS_KECCAK_PERM_BMI2)
   if(auto feat = CPUID::check(CPUID::Feature::BMI)) {
      return *feat;
   }
#endif

   return "base";
}

// void Keccak_Permutation::clear() {
//    zeroise(m_S);
//    m_S_inpos = 0;
//    m_S_outpos = 0;
// }

void Keccak_Permutation::absorb(std::span<const uint8_t> input) {
   process(
      input,
      [](uint64_t& state_word, uint64_t input_word) { state_word ^= input_word; },
      [](uint64_t& state_word, uint64_t input_word, PartialWordBounds) { state_word ^= input_word; },
      [this] { permute(); });
}

void Keccak_Permutation::squeeze(std::span<uint8_t> output) {
   BufferStuffer output_stuffer(output);

   process(
      output,
      [&](uint64_t& state_word, uint64_t) { output_stuffer.append(store_le(state_word)); },
      [&](uint64_t& state_word, uint64_t, PartialWordBounds bounds) {
         const auto out_buffer = store_le(state_word);
         output_stuffer.append(std::span{out_buffer}.subspan(bounds.offset, bounds.length));
      },
      [this] { permute(); });
}

void Keccak_Permutation::finish() {
   // append the first bit of the final padding after the custom padding
   auto& S = state();

   uint8_t init_pad = static_cast<uint8_t>(m_custom_padding | uint64_t(1) << m_custom_padding_bit_len);
   S[cursor() / 8] ^= static_cast<uint64_t>(init_pad) << (8 * (cursor() % 8));

   // final bit of the padding of the last block
   S[(byte_rate() / 8) - 1] ^= static_cast<uint64_t>(0x80) << 56;

   permute();
}

void Keccak_Permutation::permute() {
#if defined(BOTAN_HAS_KECCAK_PERM_BMI2)
   if(CPUID::has(CPUID::Feature::BMI)) {
      return permute_bmi2();
   }
#endif

   static const uint64_t RC[24] = {0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
                                   0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
                                   0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
                                   0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
                                   0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
                                   0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008};

   uint64_t T[25];

   for(size_t i = 0; i != 24; i += 2) {
      Keccak_Permutation_round(T, state().data(), RC[i + 0]);
      Keccak_Permutation_round(state().data(), T, RC[i + 1]);
   }
}

}  // namespace Botan
