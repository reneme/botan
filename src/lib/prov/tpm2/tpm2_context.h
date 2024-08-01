/*
* TPM 2 interface
* (C) 2024 Jack Lloyd
* (C) 2024 René Meusel, Amos Treiber - Rohde & Schwarz Cybersecurity GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_TPM2_CONTEXT_H_
#define BOTAN_TPM2_CONTEXT_H_

#include <botan/exceptn.h>

#include <memory>
#include <optional>
#include <vector>

namespace Botan::TPM2 {

class BOTAN_PUBLIC_API(3, 6) Context final : public std::enable_shared_from_this<Context> {
   public:
      /**
       * @param tcti_nameconf  this is passed to Tss2_TctiLdr_Initialize verbatim
       */
      static std::shared_ptr<Context> create(const std::string& tcti_nameconf);

      /**
       * @param tcti  if set this is passed to Tss2_TctiLdr_Initialize_Ex verbatim
       *              otherwise a nullptr is passed.
       * @param conf  if set this is passed to Tss2_TctiLdr_Initialize_Ex verbatim
       *              otherwise a nullptr is passed.
       */
      static std::shared_ptr<Context> create(std::optional<std::string> tcti = {},
                                             std::optional<std::string> conf = {});

      Context(const Context&) = delete;
      Context(Context&& ctx) noexcept = default;
      ~Context();

      Context& operator=(const Context&) = delete;
      Context& operator=(Context&& ctx) noexcept = default;

      /// @return an ESYS_CONTEXT* for use in other TPM2 functions.
      void* inner_context_object();

      /// @return the Vendor of the TPM2
      std::string vendor() const;

      /// @returns the Manufacturer of the TPM2
      std::string manufacturer() const;

      std::vector<uint32_t> persistent_handles() const;

      /// @return true if @param persistent_handle is in the list of persistent handles
      bool in_persistent_handles(uint32_t persistent_handle) const;

   private:
      Context(const char* tcti_nameconf);
      Context(const char* tcti_name, const char* tcti_conf);

   private:
      struct Impl;  // PImpl to avoid TPM2-TSS includes in this header
      std::unique_ptr<Impl> m_impl;
};

}  // namespace Botan::TPM2

#endif
