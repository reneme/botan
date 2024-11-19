/*
* (C) 2024 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/spake2.h>

#include <botan/hash.h>
#include <botan/hex.h>
#include <botan/pwdhash.h>
#include <botan/internal/loadstor.h>
#include <botan/internal/stl_util.h>

#include <utility>

namespace Botan {

namespace {

auto store_le64(uint64_t n) -> std::array<uint8_t, 8> {
   return store_le(n);
}

std::vector<uint8_t> format_spake2_ad(std::span<const uint8_t> a_identity,
                                      std::span<const uint8_t> b_identity,
                                      std::span<const uint8_t> context) {
   // clang-format off
   return concat<std::vector<uint8_t>>(store_le64(a_identity.size()), a_identity,
                                       store_le64(b_identity.size()), b_identity,
                                       store_le64(context.size()),    context);
   // clang-format on
}

const EC_AffinePoint& spake2_our_pt(const SPAKE2_Parameters& params, SPAKE2_PeerId whoami) {
   return (whoami == SPAKE2_PeerId::PeerA) ? params.spake2_m() : params.spake2_n();
}

const EC_AffinePoint& spake2_their_pt(const SPAKE2_Parameters& params, SPAKE2_PeerId whoami) {
   return (whoami == SPAKE2_PeerId::PeerA) ? params.spake2_n() : params.spake2_m();
}

auto spake2_sort_messages(SPAKE2_PeerId whoami, std::span<const uint8_t> ours, std::span<const uint8_t> theirs) {
   if(whoami == SPAKE2_PeerId::PeerB) {
      std::swap(ours, theirs);
   }
   return std::make_pair(ours, theirs);
}

}  // namespace

EC_Scalar SPAKE2_Parameters::hash_shared_secret(const EC_Group& group,
                                                std::string_view shared_secret,
                                                std::span<const uint8_t> a_identity,
                                                std::span<const uint8_t> b_identity,
                                                std::span<const uint8_t> context) {
   constexpr size_t M = 128 * 1024;
   constexpr size_t t = 3;
   constexpr size_t p = 1;

   const auto ad = format_spake2_ad(a_identity, b_identity, context);

   auto pwhash_fam = PasswordHashFamily::create_or_throw("Argon2id");
   auto pwhash = pwhash_fam->from_params(M, t, p);

   // RFC 9382 Section 3.2
   //    Standards, such as NIST.SP.800-56Ar3, suggest taking mod p of a hash
   //    value that is 64 bits longer than that needed to represent p to remove
   //    statistical bias introduced by the modulation.
   secure_vector<uint8_t> w_bytes(group.get_order_bytes() + 16);
   pwhash->hash(w_bytes, shared_secret, {}, ad, {});

   return EC_Scalar::from_bytes_mod_order(group, w_bytes);
}

SPAKE2_Parameters::SPAKE2_Parameters(const EC_Group& group,
                                     std::string_view shared_secret,
                                     std::span<const uint8_t> a_identity,
                                     std::span<const uint8_t> b_identity,
                                     std::span<const uint8_t> context,
                                     std::string_view hash,
                                     bool per_user_params) :
      SPAKE2_Parameters(group,
                        SPAKE2_Parameters::hash_shared_secret(group, shared_secret, a_identity, b_identity, context),
                        a_identity,
                        b_identity,
                        context,
                        hash,
                        per_user_params) {}

namespace {

std::pair<EC_AffinePoint, EC_AffinePoint> spake2_params(const EC_Group& group,
                                                        std::string_view hash,
                                                        std::span<const uint8_t> a_identity,
                                                        std::span<const uint8_t> b_identity,
                                                        std::span<const uint8_t> context,
                                                        bool per_user_params) {
   BOTAN_ARG_CHECK(group.has_cofactor() == false, "SPAKE2 not supported with this curve");

   if(per_user_params) {
      auto input = format_spake2_ad(a_identity, b_identity, context);

      auto as_span = [](std::string_view domsep) {
         return std::span(cast_char_ptr_to_uint8(domsep.data()), domsep.size());
      };

      auto m = EC_AffinePoint::hash_to_curve_ro(group, hash, input, as_span("SPAKE M"));
      auto n = EC_AffinePoint::hash_to_curve_ro(group, hash, input, as_span("SPAKE N"));

      return std::make_pair(m, n);
   } else {
      const OID& group_id = group.get_curve_oid();

      auto decode_pt = [&](std::string_view pt) -> EC_AffinePoint { return EC_AffinePoint(group, hex_decode(pt)); };

      if(group_id == OID{1, 2, 840, 10045, 3, 1, 7}) {  // secp256r1
         auto m = decode_pt("02886e2f97ace46e55ba9dd7242579f2993b64e16ef3dcab95afd497333d8fa12f");
         auto n = decode_pt("03d8bbd6c639c62937b04d997f38c3770719c629d7014d49a24b4f98baa1292b49");
         return std::make_pair(m, n);
      } else if(group_id == OID{1, 3, 132, 0, 34}) {  // secp384r1
         auto m = decode_pt(
            "030ff0895ae5ebf6187080a82d82b42e2765e3b2f8749c7e05eba366434b363d3dc36f15314739074d2eb8613fceec2853");
         auto n = decode_pt(
            "02c72cf2e390853a1c1c4ad816a62fd15824f56078918f43f922ca21518f9c543bb252c5490214cf9aa3f0baab4b665c10");
         return std::make_pair(m, n);
      } else if(group_id == OID{1, 3, 132, 0, 35}) {  // secp521r1
         auto m = decode_pt(
            "02003f06f38131b2ba2600791e82488e8d20ab889af753a41806c5db18d37d85608cfae06b82e4a72cd744c719193562a653ea1f119eef9356907edc9b56979962d7aa");
         auto n = decode_pt(
            "0200c7924b9ec017f3094562894336a53c50167ba8c5963876880542bc669e494b2532d76c5b53dfb349fdf69154b9e0048c58a42e8ed04cef052a3bc349d95575cd25");
         return std::make_pair(m, n);
      } else {
         throw Not_Implemented("There are no defined SPAKE2 parameters for this curve");
      }
   }
}

}  // namespace

SPAKE2_Parameters::SPAKE2_Parameters(const EC_Group& group,
                                     const EC_Scalar& shared_secret,
                                     std::span<const uint8_t> a_identity,
                                     std::span<const uint8_t> b_identity,
                                     std::span<const uint8_t> context,
                                     std::string_view hash,
                                     bool per_user_params) :
      m_group(group),
      m_params(spake2_params(m_group, hash, a_identity, b_identity, context, per_user_params)),
      m_w(shared_secret),
      m_hash_fn(hash),
      m_a_identity(a_identity.begin(), a_identity.end()),
      m_b_identity(b_identity.begin(), b_identity.end()) {}

struct SPAKE2_Context::Internal {
      std::vector<uint8_t> message;
      EC_Scalar ephemeral_key;
};

SPAKE2_Context::State::State(std::unique_ptr<Internal> i) : internal(std::move(i)) {}

SPAKE2_Context::State::~State() = default;

SPAKE2_Context::State::State(State&&) noexcept = default;
SPAKE2_Context::State& SPAKE2_Context::State::operator=(State&&) noexcept = default;

std::pair<std::vector<uint8_t>, SPAKE2_Context::State> SPAKE2_Context::generate_message() {
   auto eph_key = EC_Scalar::random(m_params.group(), m_rng);

   const auto& N_or_M = spake2_our_pt(m_params, m_whoami);
   const auto& g = EC_AffinePoint::generator(m_params.group());
   // Compute g*x + w*{M,N}
   auto msg = EC_AffinePoint::mul_px_qy(g, eph_key, N_or_M, m_params.spake2_w(), m_rng).serialize_uncompressed();

   return {msg, std::make_unique<SPAKE2_Context::Internal>(msg, std::move(eph_key))};
}

secure_vector<uint8_t> SPAKE2_Context::process_message(State s, std::span<const uint8_t> peer_message) {
   auto state = std::exchange(s.internal, {});
   BOTAN_STATE_CHECK(state != nullptr);

   // Reject anything except uncompressed points
   if(peer_message.empty() || peer_message[0] != 0x04) {
      throw Decoding_Error("SPAKE2 key share was invalid");
   }

   // Will throw if not on the curve
   EC_AffinePoint peer_pt(m_params.group(), peer_message);

   const auto& [our_message, eph_key] = *state;
   const auto& N_or_M = spake2_their_pt(m_params, m_whoami);
   // Compute x*(pt-w*N_or_M)
   const auto neg_xw = eph_key.negate() * m_params.spake2_w();
   const auto K = EC_AffinePoint::mul_px_qy(peer_pt, eph_key, N_or_M, neg_xw, m_rng);

   auto hash_fn = HashFunction::create_or_throw(m_params.hash_function());

   auto append_to_hash_with_le64 = [&](std::span<const uint8_t> data) {
      hash_fn->update(store_le64(data.size()));
      hash_fn->update(data);
   };

   auto [pA, pB] = spake2_sort_messages(m_whoami, our_message, peer_message);

   // Calculate TT
   append_to_hash_with_le64(m_params.a_identity());
   append_to_hash_with_le64(m_params.b_identity());
   append_to_hash_with_le64(pA);
   append_to_hash_with_le64(pB);
   append_to_hash_with_le64(K.serialize_uncompressed());
   append_to_hash_with_le64(m_params.spake2_w().serialize());

   return hash_fn->final();
}

}  // namespace Botan
