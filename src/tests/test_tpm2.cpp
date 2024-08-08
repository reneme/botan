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

#if defined(BOTAN_HAS_TPM2)
   #include <botan/internal/tpm2_hash.h>

   #include <botan/tpm2_rng.h>
   #include <botan/tpm2_rsa.h>
   #include <botan/tpm2_session.h>
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
   if(ctx->vendor() != "SW   TPM" || ctx->manufacturer() != "IBM") {
      return {};
   }

   if(ctx->supports_botan_crypto_backend()) {
      ctx->use_botan_crypto_backend(Test::new_rng(__func__));
   }

   return ctx;
}

Test::Result bail_out() {
   Test::Result result("TPM2 test bail out");
   result.test_failure("Not sure we're on a simulated TPM2, cautiously refusing any action.");
   return result;
}

std::vector<Test::Result> test_tpm2_properties() {
   auto ctx = get_tpm2_context();
   if(!ctx) {
      return {bail_out()};
   }

   return {
      CHECK("Vendor and Manufacturer",
            [&](Test::Result& result) {
               result.test_eq("Vendor", ctx->vendor(), "SW   TPM");
               result.test_eq("Manufacturer", ctx->manufacturer(), "IBM");
            }),

      CHECK("Max random bytes per request",
            [&](Test::Result& result) {
               const auto prop = ctx->max_random_bytes_per_request();
               result.test_gte("at least as long as SHA-256", prop, 32);
               result.test_lte("at most as long as SHA-512", prop, 64);
            }),
   };
}

std::vector<Test::Result> test_tpm2_context() {
   auto ctx = get_tpm2_context();
   if(!ctx) {
      return {bail_out()};
   }

   const auto persistent_key_id = Test::options().tpm2_persistent_rsa_handle();

   return {
      CHECK("Persistent handles",
            [&](Test::Result& result) {
               const auto handles = ctx->persistent_handles();
               result.confirm("At least one persistent handle", !handles.empty());
               result.confirm("SRK is in the list", Botan::value_exists(handles, 0x81000001));
               result.confirm("Test private key is in the list", Botan::value_exists(handles, persistent_key_id));
            }),

      CHECK("Fetch Storage Root Key",
            [&](Test::Result& result) {
               auto srk = ctx->storage_root_key({}, {});
               result.require("SRK is not null", srk != nullptr);
               result.test_eq("Algo", srk->algo_name(), "RSA");
               result.test_eq("Key size", srk->key_length(), 2048);
               result.confirm("Has persistent handle", srk->handles().has_persistent_handle());
            }),
   };
}

std::vector<Test::Result> test_tpm2_rng() {
   auto ctx = get_tpm2_context();
   if(!ctx) {
      return {bail_out()};
   }

   auto rng = Botan::TPM2::RNG(ctx, Botan::TPM2::Session::unauthenticated_session(ctx));

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
std::unique_ptr<KeyT> load_persistent(Test::Result& result,
                                      const std::shared_ptr<Botan::TPM2::Context>& ctx,
                                      uint32_t persistent_key_id,
                                      std::span<const uint8_t> auth_value,
                                      const std::shared_ptr<Botan::TPM2::Session>& session) {
   const auto persistent_handles = ctx->persistent_handles();
   result.confirm(
      "Persistent key available",
      std::find(persistent_handles.begin(), persistent_handles.end(), persistent_key_id) != persistent_handles.end());

   auto key = [&] {
      if constexpr(std::same_as<Botan::TPM2::RSA_PublicKey, KeyT>) {
         return KeyT::from_persistent(ctx, persistent_key_id, session);
      } else {
         return KeyT::from_persistent(ctx, persistent_key_id, auth_value, session);
      }
   }();

   result.test_eq("Algo", key->algo_name(), "RSA" /* TODO ECC support*/);
   result.test_is_eq("Handle", key->handles().persistent_handle(), persistent_key_id);
   return key;
}

std::vector<Test::Result> test_tpm2_rsa() {
   auto ctx = get_tpm2_context();
   if(!ctx) {
      return {bail_out()};
   }

   auto session = Botan::TPM2::Session::unauthenticated_session(ctx);

   const auto persistent_key_id = Test::options().tpm2_persistent_rsa_handle();
   const auto password = Test::options().tpm2_persistent_auth_value();

   return {
      CHECK("Load the private key multiple times",
            [&](Test::Result& result) {
               for(size_t i = 0; i < 20; ++i) {
                  auto key =
                     load_persistent<Botan::TPM2::RSA_PrivateKey>(result, ctx, persistent_key_id, password, session);
                  result.test_eq(Botan::fmt("Key loaded successfully ({})", i), key->algo_name(), "RSA");
               }
            }),

      CHECK("Sign a message",
            [&](Test::Result& result) {
               auto key =
                  load_persistent<Botan::TPM2::RSA_PrivateKey>(result, ctx, persistent_key_id, password, session);

               Botan::Null_RNG null_rng;
               Botan::PK_Signer signer(*key, null_rng /* TPM takes care of this */, "PSS(SHA-256)");

               // create a message that is larger than the TPM2 max buffer size
               const auto message = [] {
                  std::vector<uint8_t> msg(TPM2_MAX_DIGEST_BUFFER + 5);
                  for(size_t i = 0; i < msg.size(); ++i) {
                     msg[i] = static_cast<uint8_t>(i);
                  }
                  return msg;
               }();
               const auto signature = signer.sign_message(message, null_rng);
               result.require("signature is not empty", !signature.empty());

               auto public_key = key->public_key();
               Botan::PK_Verifier verifier(*public_key, "PSS(SHA-256)");
               result.confirm("Signature is valid", verifier.verify_message(message, signature));
            }),

      CHECK("verify signature",
            [&](Test::Result& result) {
               auto sign = [&](std::span<const uint8_t> message) {
                  auto key =
                     load_persistent<Botan::TPM2::RSA_PrivateKey>(result, ctx, persistent_key_id, password, session);
                  Botan::Null_RNG null_rng;
                  Botan::PK_Signer signer(*key, null_rng /* TPM takes care of this */, "PSS(SHA-256)");
                  return signer.sign_message(message, null_rng);
               };

               auto verify = [&](std::span<const uint8_t> msg, std::span<const uint8_t> sig) {
                  auto key =
                     load_persistent<Botan::TPM2::RSA_PublicKey>(result, ctx, persistent_key_id, password, session);
                  Botan::PK_Verifier verifier(*key, "PSS(SHA-256)");
                  return verifier.verify_message(msg, sig);
               };

               const auto message = Botan::hex_decode("baadcafe");
               const auto signature = sign(message);

               result.confirm("verification successful", verify(message, signature));

               // change the message
               auto rng = Test::new_rng(__func__);
               auto mutated_message = Test::mutate_vec(message, *rng);
               result.confirm("verification failed", !verify(mutated_message, signature));

               // ESAPI manipulates the session attributes internally and does
               // not reset them when an error occurs. A failure to validate a
               // signature is an error, and hence behaves surprisingly by
               // leaving the session attributes in an unexpected state.
               // The Botan wrapper has a workaround for this...
               const auto attrs = session->attributes();
               result.confirm("encrypt flag was not cleared by ESAPI", attrs.encrypt);

               // orignal message again
               result.confirm("verification still successful", verify(message, signature));
            }),

      CHECK("sign and verify multiple messages with the same Signer/Verifier objects",
            [&](Test::Result& result) {
               const std::vector<std::vector<uint8_t>> messages = {
                  Botan::hex_decode("BAADF00D"),
                  Botan::hex_decode("DEADBEEF"),
                  Botan::hex_decode("CAFEBABE"),
               };

               // Generate a few signatures, then deallocate the private key.
               auto signatures = [&] {
                  auto sk =
                     load_persistent<Botan::TPM2::RSA_PrivateKey>(result, ctx, persistent_key_id, password, session);
                  Botan::Null_RNG null_rng;
                  Botan::PK_Signer signer(*sk, null_rng /* TPM takes care of this */, "PSS(SHA-256)");
                  std::vector<std::vector<uint8_t>> sigs;
                  sigs.reserve(messages.size());
                  for(const auto& message : messages) {
                     sigs.emplace_back(signer.sign_message(message, null_rng));
                  }
                  return sigs;
               }();

               // verify via TPM 2.0
               auto pk = load_persistent<Botan::TPM2::RSA_PublicKey>(result, ctx, persistent_key_id, password, session);
               Botan::PK_Verifier verifier(*pk, "PSS(SHA-256)");
               for(size_t i = 0; i < messages.size(); ++i) {
                  result.confirm(Botan::fmt("verification successful ({})", i),
                                 verifier.verify_message(messages[i], signatures[i]));
               }

               // verify via software
               auto soft_pk = Botan::RSA_PublicKey(pk->algorithm_identifier(), pk->public_key_bits());
               Botan::PK_Verifier soft_verifier(soft_pk, "PSS(SHA-256)");
               for(size_t i = 0; i < messages.size(); ++i) {
                  result.confirm(Botan::fmt("software verification successful ({})", i),
                                 soft_verifier.verify_message(messages[i], signatures[i]));
               }
            }),

      CHECK("Wrong password is not accepted during signing",
            [&](Test::Result& result) {
               auto key = load_persistent<Botan::TPM2::RSA_PrivateKey>(
                  result, ctx, persistent_key_id, Botan::hex_decode("deadbeef"), session);

               Botan::Null_RNG null_rng;
               Botan::PK_Signer signer(*key, null_rng /* TPM takes care of this */, "PSS(SHA-256)");

               const auto message = Botan::hex_decode("baadcafe");
               result.test_throws<Botan::TPM2::Error>("Fail with wrong password",
                                                      [&] { signer.sign_message(message, null_rng); });
            }),

      CHECK("Cannot export private key blob from persistent key",
            [&](Test::Result& result) {
               auto key =
                  load_persistent<Botan::TPM2::RSA_PrivateKey>(result, ctx, persistent_key_id, password, session);
               result.test_throws<Botan::Not_Implemented>("Export private key blob not implemented",
                                                          [&] { key->private_key_bits(); });
            }),

      CHECK("Create a new transient key",
            [&](Test::Result& result) {
               auto srk = ctx->storage_root_key({}, {});

               const std::array<uint8_t, 6> secret = {'s', 'e', 'c', 'r', 'e', 't'};

               auto sk = Botan::TPM2::RSA_PrivateKey(ctx, *srk, secret, session, 2048);
               result.confirm("is transient", sk.handles().has_transient_handle());
               result.confirm("is not persistent", !sk.handles().has_persistent_handle());

               const auto sk_blob = sk.private_key_bits();
               const auto pk = sk.public_key();

               // Perform a round-trip sign/verify test with the new key pair
               std::vector<uint8_t> message = {'h', 'e', 'l', 'l', 'o'};
               Botan::Null_RNG null_rng;
               Botan::PK_Signer signer(sk, null_rng /* TPM takes care of this */, "PSS(SHA-256)");
               const auto signature = signer.sign_message(message, null_rng);
               result.require("signature is not empty", !signature.empty());

               Botan::PK_Verifier verifier(*pk, "PSS(SHA-256)");
               result.confirm("Signature is valid", verifier.verify_message(message, signature));
            }),
   };
}

std::vector<Test::Result> test_tpm2_hash() {
   auto ctx = get_tpm2_context();
   if(!ctx) {
      return {bail_out()};
   }

   auto test = [&](Test::Result& result, std::string_view algo) {
      auto tpm_hash = [&]() -> std::unique_ptr<Botan::TPM2::HashFunction> {
         try {
            return std::make_unique<Botan::TPM2::HashFunction>(
               ctx, algo, ESYS_TR_RH_NULL, Botan::TPM2::Session::unauthenticated_session(ctx));
         } catch(const Botan::Lookup_Error&) {
            return {};
         }
      }();
      auto soft_hash = Botan::HashFunction::create(algo);

      if(!tpm_hash) {
         result.test_note(Botan::fmt("Skipping {}, TPM 2.0 does not support it", algo));
         return;
      }

      if(!soft_hash) {
         result.test_note(Botan::fmt("Skipping {}, no software equivalent available", algo));
         return;
      }

      result.test_eq("Name", tpm_hash->name(), soft_hash->name());
      result.test_eq("Output length", tpm_hash->output_length(), soft_hash->output_length());

      // multiple update calls
      tpm_hash->update("Hello, ");
      tpm_hash->update("world!");
      result.test_eq("digest (multi-update)", tpm_hash->final(), soft_hash->process("Hello, world!"));

      // single process call
      result.test_eq("digest (single-process)", tpm_hash->process("Hallo, Welt."), soft_hash->process("Hallo, Welt."));

      // create a message that is larger than the TPM2 max buffer size
      const auto long_message = [] {
         std::vector<uint8_t> msg(TPM2_MAX_DIGEST_BUFFER + 5);
         for(size_t i = 0; i < msg.size(); ++i) {
            msg[i] = static_cast<uint8_t>(i);
         }
         return msg;
      }();

      tpm_hash->update(long_message);
      result.test_eq("digest (long msg via update)", tpm_hash->final(), soft_hash->process(long_message));
      result.test_eq(
         "digest (long msg via process)", tpm_hash->process(long_message), soft_hash->process(long_message));

      // test clear
      tpm_hash->update("Hello");
      tpm_hash->clear();
      tpm_hash->update("Bonjour");
      result.test_eq("digest (clear)", tpm_hash->final(), soft_hash->process("Bonjour"));

      // new_object
      auto new_tpm_hash = tpm_hash->new_object();
      result.test_eq("Name (new_object)", new_tpm_hash->name(), tpm_hash->name());
      result.test_eq("Output length (new_object)", new_tpm_hash->output_length(), tpm_hash->output_length());
      result.test_eq("digest (new object)",
                     new_tpm_hash->process("Salut tout le monde!"),
                     soft_hash->process("Salut tout le monde!"));
   };

   return {
      CHECK("SHA-1", [&](Test::Result& result) { test(result, "SHA-1"); }),
      CHECK("SHA-256", [&](Test::Result& result) { test(result, "SHA-256"); }),
      CHECK("SHA-384", [&](Test::Result& result) { test(result, "SHA-384"); }),
      CHECK("SHA-512", [&](Test::Result& result) { test(result, "SHA-512"); }),
      CHECK("SHA-3(256)", [&](Test::Result& result) { test(result, "SHA-3(256)"); }),
      CHECK("SHA-3(384)", [&](Test::Result& result) { test(result, "SHA-3(384)"); }),
      CHECK("SHA-3(512)", [&](Test::Result& result) { test(result, "SHA-3(512)"); }),

      CHECK("lookup error",
            [&](Test::Result& result) {
               result.test_throws<Botan::Lookup_Error>(
                  "Lookup error", [&] { [[maybe_unused]] auto _ = Botan::TPM2::HashFunction(ctx, "MD-5"); });
            }),

      CHECK("copy_state is not implemented",
            [&](Test::Result& result) {
               auto tpm_hash = Botan::TPM2::HashFunction(ctx, "SHA-256");
               result.test_throws<Botan::Not_Implemented>("TPM2 hash does not support copy_state",
                                                          [&] { [[maybe_unused]] auto _ = tpm_hash.copy_state(); });
            }),

      CHECK("validation ticket",
            [&](Test::Result& result) {
               // using the NULL hierarchy essentially disables the validation ticket
               auto tpm_hash_null = Botan::TPM2::HashFunction(
                  ctx, "SHA-256", ESYS_TR_RH_NULL, Botan::TPM2::Session::unauthenticated_session(ctx));
               tpm_hash_null.update("Hola mundo!");
               const auto [digest_null, ticket_null] = tpm_hash_null.final_with_ticket();
               result.require("digest is set", digest_null != nullptr);
               result.require("ticket is set", ticket_null != nullptr);
               result.confirm("ticket is empty", ticket_null->digest.size == 0);

               // using the OWNER hierarchy (for instance) enables the validation ticket
               auto tpm_hash_owner = Botan::TPM2::HashFunction(
                  ctx, "SHA-256", ESYS_TR_RH_OWNER, Botan::TPM2::Session::unauthenticated_session(ctx));
               tpm_hash_owner.update("Hola mundo!");
               const auto [digest_owner, ticket_owner] = tpm_hash_owner.final_with_ticket();
               result.require("digest is set", digest_owner != nullptr);
               result.require("ticket is set", ticket_owner != nullptr);
               result.confirm("ticket is not empty", ticket_owner->digest.size > 0);

               const auto digest_vec = Botan::TPM2::copy_into<Botan::secure_vector<uint8_t>>(*digest_owner);
               result.test_eq("digest",
                              digest_vec,
                              Botan::hex_decode("1e479f4d871e59e9054aad62105a259726801d5f494acbfcd40591c82f9b3136"));

               result.test_eq("digests are the same, regardless of ticket",
                              Botan::TPM2::copy_into<std::vector<uint8_t>>(*digest_null),
                              digest_vec);
            }),
   };
}

}  // namespace

BOTAN_REGISTER_TEST_FN("tpm2", "tpm2_props", test_tpm2_properties);
BOTAN_REGISTER_TEST_FN("tpm2", "tpm2_ctx", test_tpm2_context);
BOTAN_REGISTER_TEST_FN("tpm2", "tpm2_rng", test_tpm2_rng);
BOTAN_REGISTER_TEST_FN("tpm2", "tpm2_rsa", test_tpm2_rsa);
BOTAN_REGISTER_TEST_FN("tpm2", "tpm2_hash", test_tpm2_hash);

#endif

}  // namespace Botan_Tests
