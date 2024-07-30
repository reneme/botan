/*
* TPM 2.0 Hash Function Wrappers
* (C) 2024 Jack Lloyd
* (C) 2024 René Meusel, Amos Treiber - Rohde & Schwarz Cybersecurity GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/tpm2_hash.h>

#include <botan/internal/fmt.h>
#include <botan/internal/stl_util.h>

#include <tss2/tss2_esys.h>

namespace Botan::TPM2 {

namespace {

TPMI_ALG_HASH get_tpm2_hash_type(std::string_view hash_name) {
   if(hash_name == "SHA-1") {
      return TPM2_ALG_SHA1;
   } else if(hash_name == "SHA-256") {
      return TPM2_ALG_SHA256;
   } else if(hash_name == "SHA-384") {
      return TPM2_ALG_SHA384;
   } else if(hash_name == "SHA-512") {
      return TPM2_ALG_SHA512;
   } else if(hash_name == "SHA-3(256)") {
      return TPM2_ALG_SHA3_256;
   } else if(hash_name == "SHA-3(384)") {
      return TPM2_ALG_SHA3_384;
   } else if(hash_name == "SHA-3(512)") {
      return TPM2_ALG_SHA3_512;
   }

   throw Lookup_Error("TPM 2.0 Hash ", hash_name);
}

}  // namespace

HashFunction::HashFunction(std::shared_ptr<Context> ctx, std::string_view algorithm) :
      m_hash_type(get_tpm2_hash_type(algorithm)), m_handle(std::move(ctx)) {
   lazy_setup();
}

std::string HashFunction::name() const {
   switch(m_hash_type) {
      case TPM2_ALG_SHA1:
         return "SHA-1";
      case TPM2_ALG_SHA256:
         return "SHA-256";
      case TPM2_ALG_SHA384:
         return "SHA-384";
      case TPM2_ALG_SHA512:
         return "SHA-512";
      case TPM2_ALG_SHA3_256:
         return "SHA-3(256)";
      case TPM2_ALG_SHA3_384:
         return "SHA-3(384)";
      case TPM2_ALG_SHA3_512:
         return "SHA-3(512)";
   }

   throw Invalid_State("TPM 2.0 hash object with unexpected hash type");
}

size_t HashFunction::output_length() const {
   switch(m_hash_type) {
      case TPM2_ALG_SHA1:
         return 20;
      case TPM2_ALG_SHA256:
         return 32;
      case TPM2_ALG_SHA384:
         return 48;
      case TPM2_ALG_SHA512:
         return 64;
      case TPM2_ALG_SHA3_256:
         return 32;
      case TPM2_ALG_SHA3_384:
         return 48;
      case TPM2_ALG_SHA3_512:
         return 64;
   }

   throw Invalid_State("TPM 2.0 hash object with unexpected hash type");
}

void HashFunction::clear() {
   m_handle._reset();
}

std::unique_ptr<Botan::HashFunction> HashFunction::copy_state() const {
   throw Not_Implemented("TPM 2.0 hash functions do not support copy_state");
}

std::unique_ptr<Botan::HashFunction> HashFunction::new_object() const {
   return std::make_unique<HashFunction>(m_handle.context(), name());
}

void HashFunction::lazy_setup() {
   if(m_handle.has_transient_handle()) {
      return;
   }

   const auto auth = init_empty<TPM2B_AUTH>();
   const auto rc = check_rc_expecting<TPM2_RC_HASH>("Esys_HashSequenceStart",
                                                    Esys_HashSequenceStart(inner(m_handle.context()),
                                                                           m_handle.context()->session_handle(0),
                                                                           m_handle.context()->session_handle(1),
                                                                           m_handle.context()->session_handle(2),
                                                                           &auth,
                                                                           m_hash_type,
                                                                           out_transient_handle(m_handle)));

   if(rc == TPM2_RC_HASH) {
      throw Lookup_Error(fmt("TPM 2.0 Hash {} is not supported", name()));
   }
}

void HashFunction::add_data(std::span<const uint8_t> input) {
   lazy_setup();

   BufferSlicer slicer(input);
   while(slicer.remaining() > 0) {
      const size_t chunk = std::min(slicer.remaining(), size_t(TPM2_MAX_DIGEST_BUFFER));
      const auto data = copy_into<TPM2B_MAX_BUFFER>(slicer.take(chunk));
      check_rc("Esys_SequenceUpdate",
               Esys_SequenceUpdate(inner(m_handle.context()),
                                   m_handle.transient_handle(),
                                   m_handle.context()->session_handle(0),
                                   m_handle.context()->session_handle(1),
                                   m_handle.context()->session_handle(2),
                                   &data));
   }
   BOTAN_ASSERT_NOMSG(slicer.empty());
}

std::pair<unique_esys_ptr<TPM2B_DIGEST>, unique_esys_ptr<TPMT_TK_HASHCHECK>> HashFunction::final_with_ticket() {
   BOTAN_STATE_CHECK(m_handle.has_transient_handle());

   std::pair<unique_esys_ptr<TPM2B_DIGEST>, unique_esys_ptr<TPMT_TK_HASHCHECK>> result;

   const auto nodata = init_empty<TPM2B_MAX_BUFFER>();
   check_rc("Esys_SequenceComplete",
            Esys_SequenceComplete(inner(m_handle.context()),
                                  m_handle.transient_handle(),
                                  m_handle.context()->session_handle(0),
                                  m_handle.context()->session_handle(1),
                                  m_handle.context()->session_handle(2),
                                  &nodata,
                                  ESYS_TR_RH_NULL,
                                  out_ptr(result.first),
                                  out_ptr(result.second)));
   BOTAN_ASSERT_NONNULL(result.first);

   m_handle._reset();

   return result;
}

void HashFunction::final_result(std::span<uint8_t> output) {
   const auto digest_and_ticket = final_with_ticket();
   BOTAN_ASSERT_NONNULL(digest_and_ticket.first);
   BOTAN_ASSERT_NOMSG(digest_and_ticket.first->size <= output.size());
   BOTAN_DEBUG_ASSERT(digest_and_ticket.first->size == output_length());

   copy_mem(output.first(output.size()), as_span(*digest_and_ticket.first));
}

}  // namespace Botan::TPM2
