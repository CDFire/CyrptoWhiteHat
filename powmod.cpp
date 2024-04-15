#include "powmod.h"

std::uintmax_t powmod(std::uintmax_t base, std::uintmax_t exp, std::uintmax_t
    mod) {
  std::uintmax_t result = 1;

  base %= mod;

  while (exp > 0) {
    if (exp % 2) {
      result = ((result % mod) * (base % mod)) % mod;
    }

    exp /= 2;
    base = ((base % mod) * (base % mod)) % mod;
  }

  return result;
}
