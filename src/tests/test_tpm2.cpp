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
   #include <botan/tpm2_rng.h>
   #include <botan/tpm2_rsa.h>
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

std::shared_ptr<Botan::TPM2::Context> get_tpm2_context() {
   auto ctx = Botan::TPM2::Context::create(Test::options().tpm2_tcti_name(), Test::options().tpm2_tcti_conf());
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

   auto session = std::make_unique<Botan::TPM2::AuthSession>(ctx);
   ctx->set_sessions(session->session(), std::nullopt, std::nullopt);

   auto rng = Botan::TPM2::RNG(ctx);

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

template <typename KeyT>
KeyT load_persistent(Test::Result& result,
                     const std::shared_ptr<Botan::TPM2::Context>& ctx,
                     uint32_t persistent_key_id,
                     std::span<const uint8_t> auth_value) {
   const auto persistent_handles = ctx->persistent_handles();
   result.confirm(
      "Persistent key available",
      std::find(persistent_handles.begin(), persistent_handles.end(), persistent_key_id) != persistent_handles.end());

   auto key = KeyT(ctx, persistent_key_id, auth_value);
   result.test_eq("Algo", key.algo_name(), "RSA" /* TODO ECC support*/);
   result.test_is_eq("Handle", key.persistent_handle(), persistent_key_id);
   return key;
}

std::vector<Test::Result> test_tpm2_rsa() {
   auto ctx = get_tpm2_context();
   if(!ctx) {
      return {bail_out()};
   }

   auto session = std::make_unique<Botan::TPM2::AuthSession>(ctx);
   ctx->set_sessions(session->session(), std::nullopt, std::nullopt);

   constexpr uint32_t persistent_key_id = TPM2_PERSISTENT_FIRST + 8;
   const std::vector<uint8_t> password = {'p', 'a', 's', 's', 'w', 'o', 'r', 'd'};

   return {
      CHECK("Sign a message",
            [&](Test::Result& result) {
               auto key = load_persistent<Botan::TPM2::RSA_PrivateKey>(result, ctx, persistent_key_id, password);

               Botan::Null_RNG null_rng;
               Botan::PK_Signer signer(key, null_rng /* TPM takes care of this */, "PSS(SHA-256)");

               // create a message that is larger than the TPM2 max buffer size
               const auto message = [] {
                  std::vector<uint8_t> result(TPM2_MAX_DIGEST_BUFFER + 5);
                  for(size_t i = 0; i < result.size(); ++i) {
                     result[i] = static_cast<uint8_t>(i);
                  }
                  return result;
               }();
               const auto signature = signer.sign_message(message, null_rng);
               result.require("signature is not empty", !signature.empty());

               auto public_key = key.public_key();
               Botan::PK_Verifier verifier(*public_key, "PSS(SHA-256)");
               result.confirm("Signature is valid", verifier.verify_message(message, signature));
            }),

      CHECK("Wrong password is not accepted during signing",
            [&](Test::Result& result) {
               auto key = load_persistent<Botan::TPM2::RSA_PrivateKey>(
                  result, ctx, persistent_key_id, Botan::hex_decode("deadbeef"));

               Botan::Null_RNG null_rng;
               Botan::PK_Signer signer(key, null_rng /* TPM takes care of this */, "PSS(SHA-256)");

               const auto message = Botan::hex_decode("baadcafe");
               result.test_throws<Botan::TPM2::Error>("Wrong password is not accepted during signing",
                                                      [&] { signer.sign_message(message, null_rng); });
            }),

      CHECK("verify signature",
            [&](Test::Result& result) {
               const auto message = Botan::hex_decode("baadcafe");
               const auto signature = [&] {
                  auto key = load_persistent<Botan::TPM2::RSA_PrivateKey>(result, ctx, persistent_key_id, password);

                  Botan::Null_RNG null_rng;
                  Botan::PK_Signer signer(key, null_rng /* TPM takes care of this */, "PSS(SHA-256)");

                  return signer.sign_message(message, null_rng);
               }();

               auto key = load_persistent<Botan::TPM2::RSA_PublicKey>(result, ctx, persistent_key_id, password);

               Botan::PK_Verifier verifier(key, "PSS(SHA-256)");
               result.confirm("verification successful", verifier.verify_message(message, signature));

               // change the message
               auto rng = Test::new_rng(__func__);
               auto mutated_signature = Test::mutate_vec(signature, *rng);

               Botan::PK_Verifier verifier2(key, "PSS(SHA-256)");
               result.confirm("verification failed", !verifier2.verify_message(message, mutated_signature));
            }),
   };
}

}  // namespace

BOTAN_REGISTER_TEST_FN("tpm2", "tpm2", test_tpm2_rng, test_tpm2_rsa);
#endif

}  // namespace Botan_Tests
