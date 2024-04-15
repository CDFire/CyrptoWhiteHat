#include "hmac_sha1.h"

#include <cstdint>
#include <cstring>

#include "sha1.h"

static void xor_block(const void *block, std::uint8_t x, void *dest) {
  for (std::size_t i = 0; i < SHA1_BLOCK_SIZE; ++i) {
    reinterpret_cast<std::uint8_t *>(dest)[i] = reinterpret_cast<const
      std::uint8_t *>(block)[i] ^ x;
  }
}

static void make_block_sized(const void *key, std::size_t key_len,
    void *block_sized_key) {
  std::memset(block_sized_key, 0, SHA1_BLOCK_SIZE);

  if (key_len > SHA1_BLOCK_SIZE) {
    sha1(key, key_len, block_sized_key);
  } else  {
    std::memcpy(block_sized_key, key, key_len);
  }
}

void hmac_sha1(const void *key, std::size_t key_len, const void *msg,
    std::size_t msg_len, void *digest) {
  std::uint8_t block_sized_key[SHA1_BLOCK_SIZE];
  make_block_sized(key, key_len, block_sized_key);

  std::uint8_t inner_key_pad[SHA1_BLOCK_SIZE];
  xor_block(block_sized_key, 0x36, inner_key_pad);

  std::uint8_t outer_key_pad[SHA1_BLOCK_SIZE];
  xor_block(block_sized_key, 0x5C, outer_key_pad);

  std::uint8_t inner_hash[SHA1_DIGEST_SIZE];
  {
    sha1_context ctx;
    sha1_reset(&ctx);
    sha1_update(&ctx, inner_key_pad, sizeof(inner_key_pad));
    sha1_update(&ctx, msg, msg_len);
    sha1_finalize(&ctx, inner_hash);
  }

  {
    sha1_context ctx;
    sha1_reset(&ctx);
    sha1_update(&ctx, outer_key_pad, sizeof(outer_key_pad));
    sha1_update(&ctx, inner_hash, sizeof(inner_hash));
    sha1_finalize(&ctx, digest);
  }
}
