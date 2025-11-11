#pragma once

#include <bit>
#include <concepts>
#include <type_traits>

namespace lynxdns
{
    namespace utility
    {
        template <std::integral T>
        T ntoh(T val)
        {
            if constexpr (std::endian::native == std::endian::little)
            {
                return std::byteswap(val);
            }
            else
            {
                return val;
            }
        }
        template <std::integral T>
        T hton(T val)
        {
            if constexpr (std::endian::native == std::endian::little)
            {
                return std::byteswap(val);
            }
            else
            {
                return val;
            }
        }
    } // namespace utility
} // namespace lynxdns