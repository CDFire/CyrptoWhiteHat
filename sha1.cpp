#include "sha1.h"

/* Perform a circular shift of the bits in a number. */
static std::uint32_t rotate_left(std::uint32_t x, unsigned int n) {
  constexpr auto BIT_COUNT = sizeof(x) * 8;
  n %= BIT_COUNT;
  return (x << n) | (x >> (BIT_COUNT - n));
}

void sha1_reset(sha1_context *p_ctx) {
  p_ctx->len = 0;
  p_ctx->block_idx = 0;

  /* Initialize starting state. */
  p_ctx->state[0] = 0x67452301;
  p_ctx->state[1] = 0xEFCDAB89;
  p_ctx->state[2] = 0x98BADCFE;
  p_ctx->state[3] = 0x10325476;
  p_ctx->state[4] = 0xC3D2E1F0;
}

/* Process the current contents of `p_ctx->block` as-is. */
static void sha1_process_block(sha1_context *p_ctx) {
  std::uint32_t words[80];

  /* Reinterpret block contents as an array of 32-bit big-endian words. */
  for (unsigned int i = 0; i < 16; ++i) {
    auto base = i * sizeof(*words);
    words[i] = (p_ctx->block[base] << 24) | (p_ctx->block[base + 1] << 16)
      | (p_ctx->block[base + 2] << 8) | p_ctx->block[base + 3];
  }

  /* Extend the original 16 words into 80 words. */
  for (unsigned int i = 16; i < 80; ++i) {
    words[i] = rotate_left(words[i - 3] ^ words[i - 8] ^ words[i - 14] ^ words[i
      - 16], 1);
  }

  auto a = p_ctx->state[0];
  auto b = p_ctx->state[1];
  auto c = p_ctx->state[2];
  auto d = p_ctx->state[3];
  auto e = p_ctx->state[4];

  /* Rounds 1 to 20. */
  for (unsigned int i = 0; i < 20; ++i) {
    auto tmp = rotate_left(a, 5) + ((b & c) | (~b & d)) + e + words[i]
      + 0x5A827999;
    e = d;
    d = c;
    c = rotate_left(b, 30);
    b = a;
    a = tmp;
  }

  /* Rounds 21 to 40. */
  for (unsigned int i = 20; i < 40; ++i) {
    auto tmp = rotate_left(a, 5) + (b ^ c ^ d) + e + words[i] + 0x6ED9EBA1;
    e = d;
    d = c;
    c = rotate_left(b, 30);
    b = a;
    a = tmp;
  }

  /* Rounds 41 to 60. */
  for (unsigned int i = 40; i < 60; ++i) {
    auto tmp = rotate_left(a, 5) + ((b & c) | (b & d) | (c & d)) + e + words[i]
      + 0x8F1BBCDC;
    e = d;
    d = c;
    c = rotate_left(b, 30);
    b = a;
    a = tmp;
  }

  /* Rounds 61 to 80. */
  for (unsigned int i = 60; i < 80; ++i) {
    auto tmp = rotate_left(a, 5) + (b ^ c ^ d) + e + words[i] + 0xCA62C1D6;
    e = d;
    d = c;
    c = rotate_left(b, 30);
    b = a;
    a = tmp;
  }

  p_ctx->state[0] += a;
  p_ctx->state[1] += b;
  p_ctx->state[2] += c;
  p_ctx->state[3] += d;
  p_ctx->state[4] += e;

  p_ctx->block_idx = 0;
}

void sha1_update(sha1_context *p_ctx, const void *data, std::size_t len) {
  auto data_bytes = reinterpret_cast<const std::uint8_t *>(data);

  while (len--) {
    p_ctx->block[p_ctx->block_idx++] = *data_bytes;
    ++p_ctx->len;

    if (p_ctx->block_idx == 64) {
      sha1_process_block(p_ctx);
    }

    ++data_bytes;
  }
}

/* Pad a message out to an appropriate length. */
static void sha1_pad_message(sha1_context *p_ctx) {
  if (p_ctx->block_idx > 55) {
    p_ctx->block[p_ctx->block_idx++] = 0x80;

    while (p_ctx->block_idx < 64) {
      p_ctx->block[p_ctx->block_idx++] = 0;
    }

    sha1_process_block(p_ctx);

    while (p_ctx->block_idx < 56) {
      p_ctx->block[p_ctx->block_idx++] = 0;
    }
  } else {
    p_ctx->block[p_ctx->block_idx++] = 0x80;

    while (p_ctx->block_idx < 56) {
      p_ctx->block[p_ctx->block_idx++] = 0;
    }
  }

  const auto len_bits = p_ctx->len * 8;

  /* Append the number of bits in the original data. */
  p_ctx->block[56] = (len_bits & 0xFF00000000000000) >> 56;
  p_ctx->block[57] = (len_bits & 0xFF000000000000) >> 48;
  p_ctx->block[58] = (len_bits & 0xFF0000000000) >> 40;
  p_ctx->block[59] = (len_bits & 0xFF00000000) >> 32;
  p_ctx->block[60] = (len_bits & 0xFF000000) >> 24;
  p_ctx->block[61] = (len_bits & 0xFF0000) >> 16;
  p_ctx->block[62] = (len_bits & 0xFF00) >> 8;
  p_ctx->block[63] = len_bits & 0xFF;

  sha1_process_block(p_ctx);
}

void sha1_finalize(sha1_context *p_ctx, void *digest) {
  sha1_pad_message(p_ctx);

  /* Write out the digest. */
  for (unsigned int i = 0; i < SHA1_DIGEST_SIZE; ++i) {
    reinterpret_cast<std::uint8_t *>(digest)[i] = p_ctx->state[i / 4] >> (8
      * (3 - (i % 4)));
  }
}

void sha1(const void *data, std::size_t len, void *digest) {
  sha1_context ctx;
  sha1_reset(&ctx);
  sha1_update(&ctx, data, len);
  sha1_finalize(&ctx, digest);
}
