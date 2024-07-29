/*
* TPM 2.0 Hash Function Wrappers
* (C) 2024 Jack Lloyd
* (C) 2024 René Meusel, Amos Treiber - Rohde & Schwarz Cybersecurity GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/
#ifndef BOTAN_TPM2_HASH_H_
#define BOTAN_TPM2_HASH_H_

#include <botan/hash.h>
#include <botan/tpm2.h>

#include <botan/tpm2_object.h>

namespace Botan::TPM2 {

class HashFunction : public Object,
                     public Botan::HashFunction {
   public:
      HashFunction(std::shared_ptr<Context> ctx, std::string_view algorithm);

      ~HashFunction() override;

      std::string name() const override;

      size_t output_length() const override;

      void clear() override;

      std::unique_ptr<Botan::HashFunction> copy_state() const override;
      std::unique_ptr<Botan::HashFunction> new_object() const override;

      void add_data(std::span<const uint8_t> input) override;

      void final_result(std::span<uint8_t> output) override;

   private:
      std::shared_ptr<Context> m_ctx;
};

}  // namespace Botan::TPM2

#endif
