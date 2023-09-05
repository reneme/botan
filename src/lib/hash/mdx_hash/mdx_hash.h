/*
* (C) 1999-2008,2023 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_MDX_HELPER_H_
#define BOTAN_MDX_HELPER_H_

#include <botan/internal/bit_ops.h>
#include <botan/internal/loadstor.h>
#include <botan/concepts.h>

#include <span>
#include <array>

namespace Botan {

enum class MD_Endian {
   Little,
   Big,
};

template <typename T>
concept mdx_hash_implementation =
    concepts::contiguous_container<typename T::digest_buffer_t> &&
    requires(typename T::digest_buffer_t& digest, std::span<const uint8_t> input, size_t blocks) {
        { T::init(digest) } -> std::same_as<void>;
        { T::compress_n(digest, input, blocks) } -> std::same_as<void>;
        T::endianness;
        T::block_bytes;
        T::ctr_bytes;
    } &&
    T::block_bytes >= 64 && is_power_of_2(T::block_bytes) &&
    T::ctr_bytes >= 8 && is_power_of_2(T::ctr_bytes) &&
    T::ctr_bytes < T::block_bytes &&
    sizeof(typename T::digest_buffer_t) >= 16;

template<mdx_hash_implementation T>
class MD_Hash final
   {
   public:
      MD_Hash() :
         m_count(0),
         m_position(0)
         {
         clear_mem(m_buffer.data(), m_buffer.size());
         T::init(m_digest);
         }

      void add_data(const uint8_t input[], size_t length)
         {
         m_count += length;

         if(m_position > 0)
            {
            const size_t take = std::min(length, T::block_bytes - m_position);

            copy_mem(&m_buffer[m_position], input, take);

            if(m_position + take == T::block_bytes)
               {
               T::compress(m_digest, m_buffer, 1);
               input += (T::block_bytes - m_position);
               length -= (T::block_bytes - m_position);
               m_position = 0;
               }
            }

         const size_t full_blocks = length / T::block_bytes;
         const size_t remaining   = length % T::block_bytes;

         if(full_blocks > 0)
            {
            T::compress(m_digest, input, full_blocks);
            }

         copy_mem(&m_buffer[m_position], input + full_blocks * T::block_bytes, remaining);
         m_position += remaining;
         }

      void final_result(uint8_t output[])
         {
         BOTAN_ASSERT_NOMSG(m_position < T::block_bytes);
         clear_mem(&m_buffer[m_position], T::block_bytes - m_position);
         m_buffer[m_position] = 0x80;

         if(m_position >= T::block_bytes - T::ctr_bytes)
            {
            T::compress(m_digest, m_buffer, 1);
            clear_mem(m_buffer, T::block_bytes);
            }

         const uint64_t bit_count = m_count * 8;

         if constexpr(T::endianness == MD_Endian::Big)
            store_be(bit_count, &m_buffer[T::block_bytes - 8]);
         else
            store_le(bit_count, &m_buffer[T::block_bytes - 8]);

         T::compress(m_digest, m_buffer, 1);

         if constexpr(T::endianness == MD_Endian::Big)
            copy_out_be(output, m_digest.size(), m_digest);
         else
            copy_out_le(output, m_digest.size(), m_digest);

         clear();
         }

      void clear()
         {
         init_fn(m_digest);
         clear_mem(m_buffer, T::block_bytes);
         m_count = 0;
         m_position = 0;
         }

   private:
      std::array<uint8_t, T::block_bytes> m_buffer;
      typename T::digest_buffer_t m_digest;
      uint64_t m_count;
      size_t m_position;
   };

}

#endif
