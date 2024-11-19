#include <botan/auto_rng.h>
#include <botan/spake2.h>

#include <functional>
#include <iostream>

std::span<const uint8_t> as_span(std::string_view s) {
   return {reinterpret_cast<const uint8_t*>(s.data()), s.size()};
}

int main() {
   // Peers A and B have to agree on all of those, including
   // the association of A and B to the individual identities.
   const auto A_id = as_span("Jack");
   const auto B_id = as_span("René");
   const auto context = as_span("botan example");
   const std::string_view password = "top!secret";
   const std::string_view hash = "SHA-256";
   const auto group = Botan::EC_Group::from_name("secp256r1");

   const auto params = Botan::SPAKE2::Parameters(group, password, A_id, B_id, context, hash);
   auto rng = Botan::AutoSeeded_RNG();

   auto setup_peer = [&](Botan::SPAKE2::PeerId id) {
      return std::pair{
         [&, id] {
            // Peers have to first generate a message. Note that this creates an
            // opaque state object that must be passed into their 'second step',
            // implemented in process_message().
            return Botan::SPAKE2::generate_message(params, id, rng);
         },
         [&, id](Botan::SPAKE2::State state, std::span<const uint8_t> message_from_peer) {
            // Use the state object from the invocation of generate_message() and
            // the message received from the peer to obtain the shared secret.
            return Botan::SPAKE2::process_message(params, id, rng, std::move(state), message_from_peer);
         },
      };
   };

   auto jack = setup_peer(Botan::SPAKE2::PeerId::PeerA);
   auto rene = setup_peer(Botan::SPAKE2::PeerId::PeerB);

   // First Jack creates a message and sends it to René
   auto [jacks_message, jacks_state] = jack.first();

   // Then René receives the messsage and creates his message to Jack
   auto [renes_message, renes_state] = rene.first();
   const auto shared_secret_rene = rene.second(std::move(renes_state), jacks_message);

   // Eventually Jack receives the reply and calculates the shared secret
   const auto shared_secret_jack = jack.second(std::move(jacks_state), renes_message);

   if(shared_secret_jack == shared_secret_rene) {
      std::cout << "agreed sucessfully\n";
   } else {
      std::cerr << "whoopsie\n";
   }

   return 0;
}
