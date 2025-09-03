/*
* Keccak Permutation
* (C) 2010,2016 Jack Lloyd
* (C) 2023 Falko Strenzke
* (C) 2023,2025 René Meusel - Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_KECCAK_PERM_H_
#define BOTAN_KECCAK_PERM_H_

#include <botan/secmem.h>
#include <botan/internal/sponge.h>
#include <span>
#include <string>

namespace Botan {

/**
* KECCAK FIPS
*
* This file implements Keccak[c] which is specified by NIST FIPS 202 [1], where
* "c" is the variable capacity of this hash primitive. Keccak[c] is not  a
* general purpose hash function, but used as the basic primitive for algorithms
* such as SHA-3 and KMAC. This is not to be confused with the "informal" general purpose hash
* function which is referred to as "Keccak" and apparently refers to the final
* submission version of the Keccak submission in the SHA-3 contest, possibly
* what is released by NIST under the name "KECCAK - Final Algorithm Package" [2].
* See also the file keccak.h for the details how the keccak hash function is defined
* in terms of the Keccak[c] – a detail which cannot be found in [1].
*
*
*
* [1] FIPS PUB 202 – FEDERAL INFORMATION PROCESSING STANDARDS PUBLICATION – SHA-3 Standard: Permutation-Based Hash and Extendable-Output Functions
*       https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf#page=28
* [2] https://csrc.nist.gov/projects/hash-functions/sha-3-project
*/
class Keccak_Permutation final : public Sponge<25, uint64_t> {
   public:
      struct Config {
            uint64_t custom_padding;         /// assumed to be init_pad || 00... || fini_pad
            uint8_t custom_padding_bit_len;  /// the bit length of the custom_padding
      };

      /**
      * @brief Instantiate a Keccak permutation
      */
      consteval explicit Keccak_Permutation(SpongeConfig sponge_config, Config keccak_config) :
            Sponge(sponge_config),
            m_custom_padding(keccak_config.custom_padding),
            m_custom_padding_bit_len(keccak_config.custom_padding_bit_len) {}

      // void clear();
      std::string provider() const;

      /**
      * @brief Absorb input data into the Keccak sponge
      *
      * This method can be called multiple times with arbitrary-length buffers.
      *
      * @param input the input data
      */
      void absorb(std::span<const uint8_t> input);

      /**
      * @brief Expand output data from the current Keccak state
      *
      * This method can be called multiple times with arbitrary-length buffers.
      *
      * @param output the designated output memory
      */
      void squeeze(std::span<uint8_t> output);

      /**
      * @brief Add final padding (as provided in the constructor) and permute
      */
      void finish();

   private:
      void permute();

#if defined(BOTAN_HAS_KECCAK_PERM_BMI2)
      void permute_bmi2();
#endif

   private:
      uint64_t m_custom_padding;
      uint8_t m_custom_padding_bit_len;
};

}  // namespace Botan

#endif
