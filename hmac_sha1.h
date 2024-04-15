#ifndef CSCI4230_HMAC_H
#define CSCI4230_HMAC_H

#include <cstddef>

void hmac_sha1(const void *key, std::size_t key_len, const void *msg,
  std::size_t msg_len, void *digest);

#endif
