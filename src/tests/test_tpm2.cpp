/*
* (C) 2024 Jack Lloyd
* (C) 2024 René Meusel, Amos Treiber Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/
#include "tests.h"

#include <botan/pubkey.h>
#include <botan/internal/fmt.h>
#include <botan/internal/loadstor.h>
#include <botan/internal/stl_util.h>
#include <botan/internal/tpm2_authsession.h>
#include <iostream>

#if defined(BOTAN_HAS_TPM2)
   #include <botan/tpm2_keys.h>
   #include <botan/tpm2_rng.h>
#endif

namespace Botan_Tests {

#if defined(BOTAN_HAS_TPM2)
namespace {

bool not_zero_64(std::span<const uint8_t> in) {
   Botan::BufferSlicer bs(in);

   while(bs.remaining() > 8) {
      if(Botan::load_be(bs.take<8>()) == 0) {
         return false;
      }
   }
   // Ignore remaining bytes

   return true;
}

std::shared_ptr<Botan::TPM2_Context> get_tpm2_context() {
   auto ctx = Botan::TPM2_Context::create(Test::options().tpm2_tcti_name(), Test::options().tpm2_tcti_conf());
   if(ctx->vendor() != "SW   TPM") {
      return {};
   }

   return ctx;
}

Test::Result bail_out() {
   Test::Result result("TPM2 test bail out");
   result.test_failure("Not sure we're on a simulated TPM2, cautiously refusing any action.");
   return result;
}

std::vector<Test::Result> test_tpm2_rng() {
   auto ctx = get_tpm2_context();
   if(!ctx) {
      return {bail_out()};
   }

   auto session = std::make_unique<Botan::TPM2_AuthSession>(ctx);
   ctx->set_sessions(session->session(), std::nullopt, std::nullopt);

   auto rng = Botan::TPM2_RNG(ctx);

   return {
      CHECK("Basic functionalities",
            [&](Test::Result& result) {
               result.confirm("Accepts input", rng.accepts_input());
               result.confirm("Is seeded", rng.is_seeded());
               result.test_eq("Right name", rng.name(), "TPM2_RNG");

               result.test_no_throw("Clear", [&] { rng.clear(); });
            }),
      CHECK("Random number generation",
            [&](Test::Result& result) {
               std::array<uint8_t, 8> buf1 = {};
               rng.randomize(buf1);
               result.confirm("Is at least not 0 (8)", not_zero_64(buf1));

               std::array<uint8_t, 15> buf2 = {};
               rng.randomize(buf2);
               result.confirm("Is at least not 0 (15)", not_zero_64(buf2));

               std::array<uint8_t, 256> buf3 = {};
               rng.randomize(buf3);
               result.confirm("Is at least not 0 (256)", not_zero_64(buf3));
            }),

      CHECK("Randomize with inputs",
            [&](Test::Result& result) {
               std::array<uint8_t, 9> buf1 = {};
               rng.randomize_with_input(buf1, std::array<uint8_t, 30>{});
               result.confirm("Randomized with inputs is at least not 0 (9)", not_zero_64(buf1));

               std::array<uint8_t, 66> buf2 = {};
               rng.randomize_with_input(buf2, std::array<uint8_t, 64>{});
               result.confirm("Randomized with inputs is at least not 0 (66)", not_zero_64(buf2));

               std::array<uint8_t, 256> buf3 = {};
               rng.randomize_with_input(buf3, std::array<uint8_t, 196>{});
               result.confirm("Randomized with inputs is at least not 0 (256)", not_zero_64(buf3));
            }),
   };
}

std::vector<Test::Result> test_tpm2_keys() {
   auto ctx = get_tpm2_context();
   if(!ctx) {
      return {bail_out()};
   }

   return {
      CHECK("Key Creation and Usage",
            [&](Test::Result& result) {
               {
                  std::cout << "###########################################\n";
                  std::cout << "create key\n";
                  std::cout << "###########################################\n";

                  auto key = Botan::TPM2_Key(ctx, 8, "password");
                  result.test_eq("Algo", key.algo_name(), "RSA");
                  result.test_is_eq("Handle", key.handle(), 0x81000008);
                  // key goes out of scope
               }

               const auto persistent_handles = ctx->persistent_handles();
               result.confirm("Key made persistent",
                              std::find(persistent_handles.begin(), persistent_handles.end(), 0x81000008) !=
                                 persistent_handles.end());

               // // TODO load key with wrong PW - this will only throw once a sig_op is needed
               // result.test_throws("Key supplied with wrong PW", [&] { Botan::TPM2_Key(ctx, 8, "password_wrong"); });

               std::cout << "###########################################\n";
               std::cout << "load key\n";
               std::cout << "###########################################\n";

               // load key with right PW
               auto key = Botan::TPM2_Key(ctx, 8, "password");
               result.test_eq("Algo", key.algo_name(), "RSA");
               result.test_is_eq("Handle", key.handle(), 0x81000008);

               Botan::Null_RNG null_rng;
               Botan::PK_Signer signer(key, null_rng /* TPM takes care of this */, "PSS(SHA-256)");

               std::cout << "###########################################\n";
               std::cout << "start signing\n";
               std::cout << "###########################################\n";

               auto session = std::make_unique<Botan::TPM2_AuthSession>(ctx);
               ctx->set_sessions(session->session(), std::nullopt, std::nullopt);

               auto message = Botan::hex_decode("deadbeef");
               const auto signature = signer.sign_message(message, null_rng);
               result.test_gt("signature is not empty", signature.size(), 0);

               std::cout << "###########################################\n";
               std::cout << "start verifying\n";
               std::cout << "###########################################\n";

               auto public_key = key.public_key();
               Botan::PK_Verifier verifier(*public_key, "PSS(SHA-256)");
               result.confirm("Signature is valid", verifier.verify_message(message, signature));
            }),
   };
}

}  // namespace

BOTAN_REGISTER_TEST_FN("tpm2", "tpm2", test_tpm2_rng, test_tpm2_keys);
#endif

}  // namespace Botan_Tests
