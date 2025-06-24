/**
 * Useful concepts that are available throughout the library
 * (C) 2023 Jack Lloyd
 *     2023 René Meusel - Rohde & Schwarz Cybersecurity
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */

#ifndef BOTAN_CONCEPTS_H_
#define BOTAN_CONCEPTS_H_

#include <botan/build.h>
#include <botan/exceptn.h>
#include <botan/span.h>

#include <type_traits>

namespace Botan {

template <typename T, typename Tag, typename... Capabilities>
class Strong;

template <typename... Ts>
struct is_strong_type : std::false_type {};

template <typename... Ts>
struct is_strong_type<Strong<Ts...>> : std::true_type {};

template <typename... Ts>
constexpr bool is_strong_type_v = is_strong_type<std::remove_const_t<Ts>...>::value;

template <typename T0 = void, typename... Ts>
struct all_same {
      static constexpr bool value = (std::is_same_v<T0, Ts> && ... && true);
};

template <typename... Ts>
static constexpr bool all_same_v = all_same<Ts...>::value;

}  // namespace Botan

#if !defined(BOTAN_CPP17_COMPATIBILITY_MODE)

   #include <concepts>
   #include <iosfwd>
   #include <ranges>

namespace Botan {

template <typename T, typename Tag, typename... Capabilities>
class Strong;

template <typename... Ts>
struct is_strong_type : std::false_type {};

template <typename... Ts>
struct is_strong_type<Strong<Ts...>> : std::true_type {};

template <typename... Ts>
constexpr bool is_strong_type_v = is_strong_type<std::remove_const_t<Ts>...>::value;

template <typename T0 = void, typename... Ts>
struct all_same {
      static constexpr bool value = (std::is_same_v<T0, Ts> && ... && true);
};

template <typename... Ts>
static constexpr bool all_same_v = all_same<Ts...>::value;

namespace detail {

/**
 * Helper type to indicate that a certain type should be automatically
 * detected based on the context.
 */
struct AutoDetect {
      constexpr AutoDetect() = delete;
};

}  // namespace detail

namespace ranges {

/**
 * Models a std::ranges::contiguous_range that (optionally) restricts its
 * value_type to ValueT. In other words: a stretch of contiguous memory of
 * a certain type (optional ValueT).
 */
template <typename T, typename ValueT = std::ranges::range_value_t<T>>
concept contiguous_range = std::ranges::contiguous_range<T> && std::same_as<ValueT, std::ranges::range_value_t<T>>;

/**
 * Models a std::ranges::contiguous_range that satisfies
 * std::ranges::output_range with an arbitrary value_type. In other words: a
 * stretch of contiguous memory of a certain type (optional ValueT) that can be
 * written to.
 */
template <typename T, typename ValueT = std::ranges::range_value_t<T>>
concept contiguous_output_range = contiguous_range<T, ValueT> && std::ranges::output_range<T, ValueT>;

/**
 * Models a range that can be turned into a std::span<>. Typically, this is some
 * form of ranges::contiguous_range.
 */
template <typename T>
concept spanable_range = std::constructible_from<std::span<const std::ranges::range_value_t<T>>, T>;

/**
 * Models a range that can be turned into a std::span<> with a static extent.
 * Typically, this is a std::array or a std::span derived from an array.
 */
// clang-format off
template <typename T>
concept statically_spanable_range = spanable_range<T> &&
                                    decltype(std::span{std::declval<T&>()})::extent != std::dynamic_extent;

// clang-format on

/**
 * Find the length in bytes of a given contiguous range @p r.
 */
inline constexpr size_t size_bytes(const spanable_range auto& r) {
   return std::span{r}.size_bytes();
}

/**
 * Check that a given range @p r has a certain statically-known byte length. If
 * the range's extent is known at compile time, this is a static check,
 * otherwise a runtime argument check will be added.
 *
 * @throws Invalid_Argument  if range @p r has a dynamic extent and does not
 *                           feature the expected byte length.
 */
template <size_t expected, spanable_range R>
inline constexpr void assert_exact_byte_length(const R& r) {
   const std::span s{r};
   if constexpr(statically_spanable_range<R>) {
      static_assert(s.size_bytes() == expected, "memory region does not have expected byte lengths");
   } else {
      if(s.size_bytes() != expected) {
         throw Invalid_Argument("Memory regions did not have expected byte lengths");
      }
   }
}

/**
 * Check that a list of ranges (in @p r0 and @p rs) all have the same byte
 * lengths. If the first range's extent is known at compile time, this will be a
 * static check for all other ranges whose extents are known at compile time,
 * otherwise a runtime argument check will be added.
 *
 * @throws Invalid_Argument  if any range has a dynamic extent and not all
 *                           ranges feature the same byte length.
 */
template <spanable_range R0, spanable_range... Rs>
inline constexpr void assert_equal_byte_lengths(const R0& r0, const Rs&... rs)
   requires(sizeof...(Rs) > 0)
{
   const std::span s0{r0};

   if constexpr(statically_spanable_range<R0>) {
      constexpr size_t expected_size = s0.size_bytes();
      (assert_exact_byte_length<expected_size>(rs), ...);
   } else {
      const size_t expected_size = s0.size_bytes();
      const bool correct_size =
         ((std::span<const std::ranges::range_value_t<Rs>>{rs}.size_bytes() == expected_size) && ...);

      if(!correct_size) {
         throw Invalid_Argument("Memory regions did not have equal lengths");
      }
   }
}

}  // namespace ranges

namespace concepts {

// TODO: C++20 provides concepts like std::ranges::range or ::sized_range
//       but at the time of this writing clang had not caught up on all
//       platforms. E.g. clang 14 on Xcode does not support ranges properly.

template <typename IterT, typename ContainerT>
concept container_iterator =
   std::same_as<IterT, typename ContainerT::iterator> || std::same_as<IterT, typename ContainerT::const_iterator>;

template <typename PtrT, typename ContainerT>
concept container_pointer =
   std::same_as<PtrT, typename ContainerT::pointer> || std::same_as<PtrT, typename ContainerT::const_pointer>;

template <typename T>
concept container = requires(T a) {
   { a.begin() } -> container_iterator<T>;
   { a.end() } -> container_iterator<T>;
   { a.cbegin() } -> container_iterator<T>;
   { a.cend() } -> container_iterator<T>;
   { a.size() } -> std::same_as<typename T::size_type>;
   typename T::value_type;
};

template <typename T>
concept contiguous_container = container<T> && requires(T a) {
   { a.data() } -> container_pointer<T>;
};

template <typename T>
concept has_empty = requires(T a) {
   { a.empty() } -> std::same_as<bool>;
};

// clang-format off
template <typename T>
concept has_bounds_checked_accessors = container<T> && (
                                          requires(T a, const T ac, typename T::size_type s) {
                                             { a.at(s) } -> std::same_as<typename T::value_type&>;
                                             { ac.at(s) } -> std::same_as<const typename T::value_type&>;
                                          } ||
                                          requires(T a, const T ac, typename T::key_type k) {
                                             { a.at(k) } -> std::same_as<typename T::mapped_type&>;
                                             { ac.at(k) } -> std::same_as<const typename T::mapped_type&>;
                                          });
// clang-format on

template <typename T>
concept resizable_container = container<T> && requires(T& c, typename T::size_type s) {
   T(s);
   c.resize(s);
};

template <typename T>
concept reservable_container = container<T> && requires(T& c, typename T::size_type s) { c.reserve(s); };

template <typename T>
concept resizable_byte_buffer =
   contiguous_container<T> && resizable_container<T> && std::same_as<typename T::value_type, uint8_t>;

template <typename T>
concept streamable = requires(std::ostream& os, T a) { os << a; };

template <class T>
concept strong_type = is_strong_type_v<T>;

template <class T>
concept contiguous_strong_type = strong_type<T> && contiguous_container<T>;

template <class T>
concept integral_strong_type = strong_type<T> && std::integral<typename T::wrapped_type>;

template <class T>
concept unsigned_integral_strong_type = strong_type<T> && std::unsigned_integral<typename T::wrapped_type>;

template <typename T, typename Capability>
concept strong_type_with_capability = T::template has_capability<Capability>();

}  // namespace concepts

}  // namespace Botan

   #define BOTAN_REQUIRES(x) requires((x))
   #define BOTAN_REQUIRES_SAME_AS(x, y) requires(std::same_as<x, y>)

   #define BOTAN_RESIZABLE_BYTE_BUFFER Botan::concepts::resizable_byte_buffer
   #define BOTAN_CONTIGUOUS_OUTPUT_RANGE Botan::ranges::contiguous_output_range
   #define BOTAN_CONTIGUOUS_RANGE Botan::ranges::contiguous_range
   #define BOTAN_CONTIGUOUS_OUTPUT_BYTE_RANGE Botan::ranges::contiguous_output_range<uint8_t>
   #define BOTAN_CONTIGUOUS_BYTE_RANGE Botan::ranges::contiguous_range<uint8_t>
   #define BOTAN_INTEGRAL std::integral
   #define BOTAN_UNSIGNED_INTEGRAL std::unsigned_integral
   #define BOTAN_CONTAINER Botan::concepts::container
   #define BOTAN_CONTIGUOUS_STRONG_TYPE Botan::concepts::contiguous_strong_type
   #define BOTAN_RESIZABLE_BYTE_BUFFER Botan::concepts::resizable_byte_buffer

#else  // BOTAN_CPP17_COMPATIBILITY_MODE

   #define BOTAN_REQUIRES(x)
   #define BOTAN_REQUIRES_SAME_AS(x, y)

   #define BOTAN_RESIZABLE_BYTE_BUFFER typename
   #define BOTAN_CONTIGUOUS_OUTPUT_RANGE typename
   #define BOTAN_CONTIGUOUS_RANGE typename
   #define BOTAN_CONTIGUOUS_OUTPUT_BYTE_RANGE typename
   #define BOTAN_CONTIGUOUS_BYTE_RANGE typename
   #define BOTAN_INTEGRAL typename
   #define BOTAN_UNSIGNED_INTEGRAL typename
   #define BOTAN_CONTAINER typename
   #define BOTAN_CONTIGUOUS_STRONG_TYPE typename
   #define BOTAN_RESIZABLE_BYTE_BUFFER typename

namespace Botan::concepts {

template <typename, typename = void>
struct has_begin_end : std::false_type {};

template <typename T>
struct has_begin_end<T, std::void_t<decltype(std::declval<T&>().begin()), decltype(std::declval<T&>().end())>>
      : std::true_type {};

template <typename, typename = void>
struct has_cbegin_cend : std::false_type {};

template <typename T>
struct has_cbegin_cend<T, std::void_t<decltype(std::declval<T&>().cbegin()), decltype(std::declval<T&>().cend())>>
      : std::true_type {};

template <typename, typename = void>
struct has_data : std::false_type {};

template <typename T>
struct has_data<T, std::void_t<decltype(std::declval<T&>().data())>> : std::true_type {};

template <typename, typename = void>
struct has_size : std::false_type {};

template <typename T>
struct has_size<T, std::void_t<decltype(std::declval<T&>().size())>> : std::true_type {};

template <typename T, typename = void>
struct is_range : std::false_type {};

template <typename T>
struct is_range<T,
                std::enable_if_t<has_begin_end<T>::value && std::is_same_v<decltype(std::begin(std::declval<T&>())),
                                                                           decltype(std::end(std::declval<T&>()))>>>
      : std::true_type {};

template <typename T>
constexpr bool is_range_v = is_range<T>::value;

template <typename T, typename = void>
struct is_contiguous_range : std::false_type {};

template <typename T>
struct is_contiguous_range<
   T,
   std::enable_if_t<is_range_v<T> && has_data<T>::value && std::is_pointer_v<decltype(std::declval<T&>().data())>>>
      : std::true_type {};

template <typename T>
constexpr bool is_contiguous_range_v = is_contiguous_range<T>::value;

template <typename T, typename = void>
struct is_contiguous_output_range : std::false_type {};

template <typename T>
struct is_contiguous_output_range<
   T,
   std::enable_if_t<is_contiguous_range_v<T> &&
                    !std::is_const_v<std::remove_pointer_t<decltype(std::declval<T&>().data())>>>> : std::true_type {};

template <typename T>
constexpr bool is_contiguous_output_range_v = is_contiguous_output_range<T>::value;

template <typename T, typename = void>
struct is_container : std::false_type {};

template <typename T>
struct is_container<T, std::enable_if_t<has_begin_end<T>::value && has_cbegin_cend<T>::value && has_size<T>::value>>
      : std::true_type {};

template <typename T>
constexpr bool is_container_v = is_container<T>::value;

template <typename T, typename = void>
struct is_contiguous_container : std::false_type {};

template <typename T>
struct is_contiguous_container<T,
                               std::enable_if_t<is_container_v<T> && has_data<T>::value &&
                                                std::is_pointer_v<decltype(std::declval<T&>().data())>>> {};

template <typename T>
constexpr bool is_contiguous_container_v = is_contiguous_container<T>::value;

}  // namespace Botan::concepts

namespace Botan::ranges {

template <typename R0, typename... Rs>
inline constexpr void assert_equal_byte_lengths(R0&& r0, Rs&&... rs) {
   static_assert(sizeof...(Rs) > 0);

   // TODO: for statically-sized ranges this could be checked at compile time,
   //       just like in C++20 mode.

   const auto expected_size = std::span{r0}.size_bytes();
   const bool correct_size = ((std::span{rs}.size_bytes() == expected_size) && ...);

   if(!correct_size) {
      throw Invalid_Argument("Memory regions did not have equal lengths");
   }
}

}  // namespace Botan::ranges

namespace std {

constexpr bool is_constant_evaluated() {
   // TODO: can this actually be implemented in C++17?
   return false;
}

}  // namespace std

#endif

#endif
