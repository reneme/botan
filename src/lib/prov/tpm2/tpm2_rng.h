/*
* TPM 2 RNG interface
* (C) 2024 Jack Lloyd
* (C) 2024 René Meusel, Amos Treiber - Rohde & Schwarz Cybersecurity GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_TPM2_RNG_H_
#define BOTAN_TPM2_RNG_H_

#include <botan/rng.h>
#include <botan/tpm2_context.h>
#include <botan/tpm2_session.h>

namespace Botan::TPM2 {
class BOTAN_PUBLIC_API(3, 6) RNG final : public Hardware_RNG {
   public:
      RNG(std::shared_ptr<Context> ctx, SessionBundle sessions = {}) :
            m_ctx(std::move(ctx)), m_sessions(std::move(sessions)) {}

      bool accepts_input() const override { return true; }

      std::string name() const override { return "TPM2_RNG"; }

      bool is_seeded() const override { return true; }

   private:
      void fill_bytes_with_input(std::span<uint8_t> output, std::span<const uint8_t> input) override;

   private:
      std::shared_ptr<Context> m_ctx;
      SessionBundle m_sessions;
};

}  // namespace Botan::TPM2

#endif
